export function createSessionLock({ timeoutMs, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout, onLock, onDeadline }) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('A positive timeout is required');
  let unlocked = false;
  let timerId = null;
  let generation = 0;
  let deadline = 0;

  function disarm() {
    if (timerId !== null) clearTimer(timerId);
    timerId = null;
  }

  function lock(reason = 'manual') {
    const wasUnlocked = unlocked;
    unlocked = false;
    deadline = 0;
    generation += 1;
    disarm();
    if (wasUnlocked) onLock?.(reason);
  }

  function arm() {
    disarm();
    const remaining = Math.max(0, deadline - now());
    timerId = setTimer(() => lock('inactivity'), remaining);
    timerId?.unref?.();
    onDeadline?.(deadline);
  }

  function checkDeadline() {
    if (unlocked && now() >= deadline) lock('inactivity');
    return unlocked;
  }

  function assertCurrent(token) {
    if (!checkDeadline() || !token || token.generation !== generation || now() >= token.deadline) {
      throw new Error('Vault is locked');
    }
  }

  function assertGeneration(mark) {
    if (mark !== generation) throw new Error('Vault session changed');
  }

  return {
    mark() {
      return generation;
    },
    assertGeneration,
    unlock(until) {
      const fresh = now() + timeoutMs;
      // A restored deadline may shorten the session but never extend it past one timeout.
      const next = until === undefined ? fresh : Math.min(Number(until), fresh);
      if (!Number.isFinite(next) || next <= now()) throw new Error('Session deadline has passed');
      generation += 1;
      unlocked = true;
      deadline = next;
      arm();
    },
    capture() {
      if (!checkDeadline()) throw new Error('Vault is locked');
      return Object.freeze({ generation, deadline });
    },
    assertCurrent,
    touch(token) {
      assertCurrent(token);
      deadline = Math.max(deadline, now() + timeoutMs);
      arm();
      return Object.freeze({ generation, deadline });
    },
    // Changing the timeout counts as activity: an unlocked session restarts its countdown.
    setTimeoutMs(ms) {
      if (!Number.isFinite(ms) || ms <= 0) throw new Error('A positive timeout is required');
      timeoutMs = ms;
      if (checkDeadline()) {
        deadline = now() + timeoutMs;
        arm();
      }
    },
    lock,
    isUnlocked() {
      return checkDeadline();
    }
  };
}
