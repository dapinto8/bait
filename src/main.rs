use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

use rand::Rng;
use windows::Win32::Foundation::{BOOL, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Console::SetConsoleCtrlHandler;
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetMessageW, SetWindowsHookExW, HHOOK, MSLLHOOKSTRUCT, MSG, WH_MOUSE_LL,
    WM_MOUSEMOVE,
};

static LAST_X: AtomicI32 = AtomicI32::new(i32::MIN);
static LAST_Y: AtomicI32 = AtomicI32::new(i32::MIN);
static LAST_MOVE_MS: AtomicI64 = AtomicI64::new(0);
static IDLE_LOGGED: AtomicBool = AtomicBool::new(false);
static IDLE_COUNT: AtomicU32 = AtomicU32::new(0);

const IDLE_PHRASES: &[&str] = &[
    "a]1 packets transmitted, 0 received, 100% packet loss",
    "segfault at 0x00007ff3 in libcurl.so.4",
    "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.42",
    "sshd[4821]: Failed password for root from 10.0.0.1",
    "WARNING: disk /dev/sda1 is 94% full",
    "cron[298]: (root) CMD (/usr/lib/apt/apt.systemd.daily)",
    "systemd[1]: Started Session 47 of user nobody.",
    "nginx: upstream timed out (110: Connection timed out)",
    "postfix/smtp[12345]: connect to mx.example.com[93.184.216.34]:25: Connection refused",
    "dbus-daemon[683]: [system] Activating via systemd: service name='org.freedesktop.thermald'",
];

unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 && wparam.0 as u32 == WM_MOUSEMOVE {
        let info = &*(lparam.0 as *const MSLLHOOKSTRUCT);
        let x = info.pt.x;
        let y = info.pt.y;

        let prev_x = LAST_X.load(Ordering::Relaxed);
        let prev_y = LAST_Y.load(Ordering::Relaxed);

        if x != prev_x || y != prev_y {
            LAST_X.store(x, Ordering::Relaxed);
            LAST_Y.store(y, Ordering::Relaxed);
            LAST_MOVE_MS.store(chrono::Utc::now().timestamp_millis(), Ordering::Relaxed);
            IDLE_LOGGED.store(false, Ordering::Relaxed);
            let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            println!("[{now}] ({x}, {y})");
        }
    }
    CallNextHookEx(HHOOK::default(), code, wparam, lparam)
}

unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> BOOL {
    let count = IDLE_COUNT.load(Ordering::Relaxed);
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    eprintln!("[{now}] idle count: {count}");
    std::process::exit(0);
}

fn main() {
    LAST_MOVE_MS.store(chrono::Utc::now().timestamp_millis(), Ordering::Relaxed);

    unsafe {
        SetConsoleCtrlHandler(Some(ctrl_handler), true).expect("failed to set ctrl handler");
    }

    let _hook = unsafe {
        SetWindowsHookExW(WH_MOUSE_LL, Some(hook_proc), None, 0)
            .expect("failed to install hook")
    };

    thread::spawn(|| {
        let mut rng = rand::thread_rng();
        loop {
            thread::sleep(Duration::from_secs(1));
            let elapsed = chrono::Utc::now().timestamp_millis() - LAST_MOVE_MS.load(Ordering::Relaxed);
            if elapsed >= 30_000 && !IDLE_LOGGED.load(Ordering::Relaxed) {
                IDLE_LOGGED.store(true, Ordering::Relaxed);
                IDLE_COUNT.fetch_add(1, Ordering::Relaxed);
                let phrase = IDLE_PHRASES[rng.gen_range(0..IDLE_PHRASES.len())];
                let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
                println!("[{now}] {phrase}");
            }
        }
    });

    let mut msg = MSG::default();
    unsafe {
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {}
    }
}
