// Copyright 2016-2024 dbus-secret-service Contributors
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::time::Duration;

use dbus::arg::RefArg;
use dbus::{arg::cast, blocking::Connection, strings::Path, Message};

use crate::proxy::prompt::{Prompt, PromptCompleted};
use crate::{Error, SecretService};

const SYSTEM_WINDOW: &str = "";
const ONE_YEAR_SECONDS: u64 = 365 * 24 * 60 * 60;

impl SecretService {
    pub(crate) fn prompt_for_create(&self, path: &Path) -> Result<Path<'static>, Error> {
        self.execute_prompt(path, handle_prompt_for_create)
    }

    pub(crate) fn prompt_for_lock_unlock_delete(&self, path: &Path) -> Result<(), Error> {
        self.execute_prompt(path, handle_prompt_for_lock_unlock_delete)
    }

    fn execute_prompt<T: Send + 'static>(
        &self,
        path: &Path,
        handler: fn(PromptCompleted) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let owner = self.prompt_service_owner()?;
        let (tx, rx): (Sender<Result<T, Error>>, Receiver<Result<T, Error>>) = channel();
        let internal_handler = move |signal: PromptCompleted, _: &Connection, _: &Message| {
            let _ = tx.send(handler(signal));
            false
        };
        let timeout = self.timeout.unwrap_or(ONE_YEAR_SECONDS);
        if timeout == 0 {
            return Err(Error::Prompt);
        }
        let one_second = Duration::from_secs(1);
        // Bind both the method call and completion signal to this provider instance.
        let proxy = self
            .connection
            .with_proxy(owner.clone(), path, Duration::from_secs(3));
        let token = proxy.match_signal(internal_handler)?;
        let result = (|| {
            proxy.prompt(SYSTEM_WINDOW)?;
            for _ in 0..timeout {
                self.connection.process(one_second)?;
                match rx.try_recv() {
                    Ok(result) => return result,
                    Err(TryRecvError::Disconnected) => return Err(Error::Unavailable),
                    Err(TryRecvError::Empty) => {}
                }
                if self.prompt_service_owner()? != owner {
                    return Err(Error::Unavailable);
                }
            }
            Err(Error::Prompt)
        })();
        let cleanup = proxy.match_stop(token, true);
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                cleanup?;
                Ok(value)
            }
        }
    }

    fn prompt_service_owner(&self) -> Result<String, Error> {
        let bus = self.connection.with_proxy(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            Duration::from_secs(3),
        );
        let result: Result<(String,), dbus::Error> = bus.method_call(
            "org.freedesktop.DBus",
            "GetNameOwner",
            (crate::ss::SS_DBUS_DEST,),
        );
        match result {
            Ok((owner,)) => Ok(owner),
            Err(error) if error.name() == Some("org.freedesktop.DBus.Error.NameHasNoOwner") => {
                Err(Error::Unavailable)
            }
            Err(error) => Err(Error::Dbus(error)),
        }
    }
}

fn handle_prompt_for_create(signal: PromptCompleted) -> Result<Path<'static>, Error> {
    if signal.dismissed {
        Err(Error::Prompt)
    } else if let Some(first) = signal.result.as_static_inner(0) {
        if let Some(path) = cast::<Path<'_>>(first) {
            Ok(path.clone().into_static())
        } else {
            println!("Cast to path failed: {first:?}");
            Err(Error::Parse)
        }
    } else {
        println!("Can't understand prompt result: {:?}", signal.result);
        Err(Error::Parse)
    }
}

fn handle_prompt_for_lock_unlock_delete(signal: PromptCompleted) -> Result<(), Error> {
    if signal.dismissed {
        Err(Error::Prompt)
    } else {
        Ok(())
    }
}
