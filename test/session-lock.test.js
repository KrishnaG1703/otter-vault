import test from 'node:test';
import assert from 'node:assert/strict';
import { createSessionLock } from '../extension/lib/session-lock.js';

function fakeScheduler() {
  let nextId = 0;
  const timers = new Map();
  return {
    setTimer(callback, delay) {
      const id = ++nextId;
      timers.set(id, { callback, delay });
      return id;
    },
    clearTimer(id) { timers.delete(id); },
    latest() { return [...timers.entries()].at(-1); },
    fire(id) {
      const timer = timers.get(id);
      timers.delete(id);
      timer.callback();
    },
    count() { return timers.size; }
  };
}

test('session tokens are invalidated by lock and deadline expiry', () => {
  const scheduler = fakeScheduler();
  let now = 1_000;
  const session = createSessionLock({
    timeoutMs: 300_000,
    now: () => now,
    setTimer: scheduler.setTimer,
    clearTimer: scheduler.clearTimer,
    onLock() {}
  });
  session.unlock();
  const token = session.capture();
  assert.doesNotThrow(() => session.assertCurrent(token));
  session.lock('manual');
  assert.throws(() => session.assertCurrent(token), /locked/i);

  session.unlock();
  const expiring = session.capture();
  now += 300_001;
  assert.throws(() => session.assertCurrent(expiring), /locked/i);
  assert.equal(session.isUnlocked(), false);
});

test('touch revalidates a captured session before extending its deadline', () => {
  const scheduler = fakeScheduler();
  let now = 0;
  const session = createSessionLock({
    timeoutMs: 300_000,
    now: () => now,
    setTimer: scheduler.setTimer,
    clearTimer: scheduler.clearTimer,
    onLock() {}
  });
  session.unlock();
  const stale = session.capture();
  session.lock();
  session.unlock();
  assert.throws(() => session.touch(stale), /locked/i);
});

test('parallel tokens remain valid until their captured deadline when a peer touches', () => {
  const scheduler = fakeScheduler();
  let now = 1_000;
  const session = createSessionLock({
    timeoutMs: 300_000,
    now: () => now,
    setTimer: scheduler.setTimer,
    clearTimer: scheduler.clearTimer,
    onLock() {}
  });
  session.unlock();
  const statusToken = session.capture();
  const firstFillToken = session.capture();
  const secondFillToken = session.capture();
  now += 10;
  const touched = session.touch(statusToken);
  assert.doesNotThrow(() => session.assertCurrent(firstFillToken));
  assert.doesNotThrow(() => session.assertCurrent(secondFillToken));
  assert.equal(session.touch(firstFillToken).deadline, touched.deadline);
  now = secondFillToken.deadline;
  assert.throws(() => session.assertCurrent(secondFillToken), /locked/i);
  assert.equal(session.isUnlocked(), true);
});

test('a later global deadline is never shortened by touching an older parallel token', () => {
  const scheduler = fakeScheduler();
  let now = 0;
  const session = createSessionLock({
    timeoutMs: 300_000,
    now: () => now,
    setTimer: scheduler.setTimer,
    clearTimer: scheduler.clearTimer,
    onLock() {}
  });
  session.unlock();
  const older = session.capture();
  now = 1_000;
  const later = session.touch(session.capture());
  now = 500;
  assert.equal(session.touch(older).deadline, later.deadline);
});

test('unlock starts a five-minute automatic lock timer', () => {
  const scheduler = fakeScheduler();
  const events = [];
  const session = createSessionLock({
    timeoutMs: 300_000,
    setTimer: scheduler.setTimer,
    clearTimer: scheduler.clearTimer,
    onLock: reason => events.push(reason)
  });
  session.unlock();
  assert.equal(session.isUnlocked(), true);
  const [timerId, timer] = scheduler.latest();
  assert.equal(timer.delay, 300_000);
  scheduler.fire(timerId);
  assert.equal(session.isUnlocked(), false);
  assert.deepEqual(events, ['inactivity']);
});

test('privileged activity resets the automatic lock timer', () => {
  const scheduler = fakeScheduler();
  const session = createSessionLock({
    timeoutMs: 300_000,
    setTimer: scheduler.setTimer,
    clearTimer: scheduler.clearTimer,
    onLock() {}
  });
  session.unlock();
  const [firstId] = scheduler.latest();
  session.touch(session.capture());
  const [secondId] = scheduler.latest();
  assert.notEqual(firstId, secondId);
  assert.equal(scheduler.count(), 1);
});

test('manual lock clears the timer and reports its reason', () => {
  const scheduler = fakeScheduler();
  const events = [];
  const session = createSessionLock({
    timeoutMs: 300_000,
    setTimer: scheduler.setTimer,
    clearTimer: scheduler.clearTimer,
    onLock: reason => events.push(reason)
  });
  session.unlock();
  session.lock('manual');
  assert.equal(session.isUnlocked(), false);
  assert.equal(scheduler.count(), 0);
  assert.deepEqual(events, ['manual']);
});

test('a restored deadline can shorten but never extend the session', () => {
  const scheduler = fakeScheduler();
  let now = 1_000;
  const deadlines = [];
  const session = createSessionLock({
    timeoutMs: 300_000,
    now: () => now,
    setTimer: scheduler.setTimer,
    clearTimer: scheduler.clearTimer,
    onDeadline: deadline => deadlines.push(deadline)
  });
  session.unlock(now + 60_000);
  assert.equal(scheduler.latest()[1].delay, 60_000);
  session.unlock(now + 10 * 300_000);
  assert.equal(session.capture().deadline, now + 300_000);
  assert.deepEqual(deadlines, [61_000, 301_000]);
  session.lock();
  assert.throws(() => session.unlock(now - 1), /passed/i);
  assert.equal(session.isUnlocked(), false);
});

test('changing the timeout restarts an unlocked countdown and applies to later unlocks', () => {
  const scheduler = fakeScheduler();
  let now = 0;
  const session = createSessionLock({ timeoutMs: 300_000, now: () => now, setTimer: scheduler.setTimer, clearTimer: scheduler.clearTimer });
  session.setTimeoutMs(1_800_000);
  assert.equal(session.isUnlocked(), false);
  session.unlock(now + 1_500_000);
  assert.equal(session.capture().deadline, 1_500_000);
  now = 100_000;
  session.setTimeoutMs(900_000);
  assert.equal(session.capture().deadline, 1_000_000);
  assert.equal(scheduler.latest()[1].delay, 900_000);
  assert.throws(() => session.setTimeoutMs(0), /positive/i);
});
