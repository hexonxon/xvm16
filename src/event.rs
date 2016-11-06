/*
 * Event scheduling
 */

use std::{thread, fmt};
use std::cmp::Ordering;
use std::sync::{Mutex};

use vm;

#[derive(Eq)]
pub struct Event {
    delay: u64,         /* Remaining delay time, saved in case we will resched */
    handler: fn(Event), /* Handler func (TODO: closure?) */
}

impl Ord for Event {
    fn cmp(&self, other: &Event) -> Ordering {
        /* We want a descending sorted order so comparison is reversed */
        other.delay.cmp(&self.delay)
    }
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Event) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Event {
    fn eq (&self, other: &Event) -> bool {
        return self.delay == other.delay;
    }
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{ delay: {}, handler {:?} }}", self.delay, self.handler as *const fn(Event))
    }
}

/**
 * Event queue
 *
 * Events are sorted by remaining delay time in descinding order (i.e. ready to fire events are
 * always at the end of the queue)
 * 
 * Why no BinaryHeap? We will need to modify delay field when traversing queue in event loop.
 * BinaryHeap doesn't give us a mut_iter and i don't what to put more RefCell-s if i can avoid it.
 */
lazy_static! {
    static ref EVENT_QUEUE: Mutex<Vec<Event>> = Mutex::new(Vec::new());
}

fn enqueue_event(ev: Event)
{
    let mut q = EVENT_QUEUE.lock().unwrap();

    /* Don't care if it found an element or not - we just need an insert position */
    match q.binary_search(&ev) {
        Ok(pos) => q.insert(pos, ev),
        Err(pos) => q.insert(pos, ev),
    };
}

/**
 * Create new event
 * New event is not yet scheduled for execution. Use schedule_event for that.
 *
 * \handler A function to call when event is fired
 */
pub fn create_event(handler: fn(Event)) -> Event {
    Event {
        delay: 0,
        handler: handler,
    }
}

/**
 * Schedule event for execution after delay
 * Already fired events can be rescheduled as well
 *
 * \delay   Event delay in guest time microseconds
 */
pub fn schedule_event(delay: u64, ev: Event) {
    let mut ev = ev;
    ev.delay = delay;
    enqueue_event(ev);
}

/**
 * Event loop
 * Check guest execution time and fire events which are due
 */
fn event_loop_worker()
{
    let mut prev_guest_time = 0;
    loop {
        if !vm::is_running() {
            continue;
        }

        let guest_time = vm::get_guest_exec_time();
        assert!(guest_time >= prev_guest_time);

        if guest_time > prev_guest_time {
            /* Guest time is in nanoseconds, event time is in microseconds */
            let elapsed_time = (guest_time - prev_guest_time) / 1000;
            let mut q = EVENT_QUEUE.lock().unwrap();

            /* We will now iterate over all stored elements and substract elapsed time from delay
             * Since we're substracting the same quantity from all elements it will not change
             * their sorted order */
            for ev in &mut *q {
                if ev.delay < elapsed_time {
                    ev.delay = 0;
                } else {
                    ev.delay -= elapsed_time;
                }
            }

            /* Do another pass over events popping and firing those that have 0 delay */
            let len = q.len();
            for i in 0..len {
                if q[len - i - 1].delay != 0 {
                    break;
                }

                let ev = q.pop().unwrap();

                debug!("Firing event {:?}", ev);
                (ev.handler)(ev);
            }
        }

        prev_guest_time = guest_time;
    }
}

/**
 * Start handling events
 */
pub fn start_event_loop()
{
    thread::spawn(|| {
        event_loop_worker();
    });
}
