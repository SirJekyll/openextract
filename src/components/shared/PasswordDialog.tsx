import { useEffect, useRef, useState } from 'react';
import { LockIcon } from './Icons';
import OrganicLoader from './OrganicLoader';
import { sidecarCall } from '../../lib/ipc';

interface Props {
  udid: string;
  backupDir?: string;
  deviceName?: string;
  error?: string | null;
  loading?: boolean;
  onSubmit: (password: string) => void;
  onCancel: () => void;
}

interface CrackState {
  digits: 4 | 6;
  jobId: string;
  tried: number;
  total: number;
}

const PARTIAL_LENGTH = 6;

export default function PasswordDialog({ udid, backupDir, deviceName, error, loading, onSubmit, onCancel }: Props) {
  const [password, setPassword] = useState('');
  const [crack, setCrack] = useState<CrackState | null>(null);
  const [crackError, setCrackError] = useState<string | null>(null);
  const [foundPassword, setFoundPassword] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [showPartial, setShowPartial] = useState(false);
  const [partialDigits, setPartialDigits] = useState<string[]>(Array(PARTIAL_LENGTH).fill(''));
  const crackRef = useRef<CrackState | null>(null);
  const partialInputRefs = useRef<(HTMLInputElement | null)[]>([]);

  useEffect(() => {
    crackRef.current = crack;
  }, [crack]);

  // Listen for crack_password.progress notifications from the sidecar for the
  // lifetime of this dialog, and stop any in-flight search if it closes.
  useEffect(() => {
    const cleanupListener = window.openextract?.onNotification?.((notification: any) => {
      if (notification.method !== 'crack_password.progress') return;
      const p = notification.params;
      if (!crackRef.current || p.job_id !== crackRef.current.jobId) return;

      if (p.phase === 'running') {
        setCrack(prev => (prev ? { ...prev, tried: p.tried, total: p.total } : prev));
      } else if (p.phase === 'done') {
        const digits = crackRef.current.digits;
        setCrack(null);
        if (p.found && p.password) {
          // Show the recovered code rather than silently unlocking with it —
          // otherwise the user has no way to write it down for next time.
          setPassword(p.password);
          setFoundPassword(p.password);
        } else if (!p.cancelled) {
          setCrackError(`No matching ${digits}-digit code found.`);
        }
      }
    });
    return () => {
      cleanupListener?.();
      if (crackRef.current) {
        sidecarCall('cancel_crack_password', { job_id: crackRef.current.jobId }).catch(() => {});
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleCrack = async (digits: 4 | 6, pattern?: string) => {
    setCrackError(null);
    try {
      const result = await sidecarCall<{ status: string; job_id?: string; total?: number; error?: string }>(
        'crack_password',
        { udid, digits, pattern, backup_dir: backupDir }
      );
      if (result.status === 'started' && result.job_id && result.total) {
        setCrack({ digits, jobId: result.job_id, tried: 0, total: result.total });
        setShowPartial(false);
      } else {
        setCrackError(result.error || 'Could not start password recovery.');
      }
    } catch (e: any) {
      setCrackError(e.message || 'Could not start password recovery.');
    }
  };

  const handlePartialDigitChange = (index: number, raw: string) => {
    const digit = raw.replace(/[^0-9]/g, '').slice(-1);
    setPartialDigits(prev => {
      const next = [...prev];
      next[index] = digit;
      return next;
    });
    if (digit && index < PARTIAL_LENGTH - 1) {
      partialInputRefs.current[index + 1]?.focus();
    }
  };

  const handlePartialKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !partialDigits[index] && index > 0) {
      partialInputRefs.current[index - 1]?.focus();
    }
  };

  const numUnknown = partialDigits.filter(d => d === '').length;
  const partialCombos = Math.pow(10, numUnknown);

  const handleStartPartialCrack = () => {
    if (numUnknown === 0) {
      setCrackError('All 6 digits are filled in — enter that as the password above and click Unlock.');
      return;
    }
    const pattern = partialDigits.map(d => d || '*').join('');
    handleCrack(6, pattern);
  };

  const handleStopCrack = () => {
    if (!crack) return;
    sidecarCall('cancel_crack_password', { job_id: crack.jobId }).catch(() => {});
  };

  const handleCopyFound = () => {
    if (!foundPassword) return;
    navigator.clipboard?.writeText(foundPassword).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {});
  };

  const percent = crack ? Math.min(100, Math.floor((crack.tried / crack.total) * 100)) : 0;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <div className="bg-base rounded-xl shadow-xl w-[380px] p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-elevated flex items-center justify-center">
            <LockIcon className="text-text-secondary" size={20} />
          </div>
          <div>
            <div className="text-sm font-medium text-text-primary">Encrypted Backup</div>
            {deviceName && (
              <div className="text-xs text-text-tertiary">{deviceName}</div>
            )}
          </div>
        </div>

        <p className="text-sm text-text-secondary mb-4">
          This backup is encrypted. Enter the password you set when creating the backup.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (password.trim()) onSubmit(password);
          }}
        >
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Backup password"
            autoFocus
            className="w-full px-3 py-2.5 border border-border-strong rounded-lg text-sm bg-base text-text-primary focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent placeholder:text-text-tertiary"
          />

          {error && (
            <div className="mt-2 text-xs text-apple-error">{error}</div>
          )}

          {foundPassword && (
            <div className="mt-2 p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 flex items-center justify-between gap-2">
              <div className="text-xs text-emerald-800">
                Found it: <span className="font-mono font-semibold tracking-wide">{foundPassword}</span>
                <span className="block text-[11px] text-emerald-700 mt-0.5">Save this somewhere — click Unlock to continue.</span>
              </div>
              <button
                type="button"
                onClick={handleCopyFound}
                className="text-xs text-emerald-700 hover:underline flex-shrink-0"
              >
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
          )}

          <div className="flex gap-2 mt-4">
            <button
              type="button"
              onClick={onCancel}
              className="flex-1 px-4 py-2.5 text-sm text-text-secondary bg-elevated rounded-lg hover:opacity-80 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!password.trim() || loading || !!crack}
              className="flex-1 px-4 py-2.5 text-sm text-white bg-accent rounded-lg hover:bg-[var(--accent-hover)] transition-colors disabled:opacity-50 disabled:cursor-not-allowed inline-flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <OrganicLoader size={20} color="#fff" />
                  <span>Unlocking…</span>
                </>
              ) : (
                'Unlock'
              )}
            </button>
          </div>
        </form>

        {!foundPassword && (
          <div className="mt-4 pt-4 border-t border-border-strong">
            {crack ? null : showPartial ? (
              <div>
                <p className="text-xs text-text-tertiary mb-2">
                  Enter any digits you remember; leave the rest blank.
                </p>
                <div className="flex gap-1.5 justify-center mb-2">
                  {partialDigits.map((d, i) => (
                    <input
                      key={i}
                      ref={(el) => { partialInputRefs.current[i] = el; }}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      value={d}
                      onChange={(e) => handlePartialDigitChange(i, e.target.value)}
                      onKeyDown={(e) => handlePartialKeyDown(i, e)}
                      className="w-9 h-10 text-center text-sm font-mono border border-border-strong rounded-lg bg-base text-text-primary focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent"
                    />
                  ))}
                </div>
                <p className="text-[11px] text-text-tertiary text-center mb-3">
                  {numUnknown === 0
                    ? 'All digits filled in'
                    : `${partialCombos.toLocaleString()} possibilit${partialCombos === 1 ? 'y' : 'ies'} to try`}
                </p>
                {crackError && (
                  <div className="mb-2 text-xs text-apple-error text-center">{crackError}</div>
                )}
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setShowPartial(false);
                      setPartialDigits(Array(PARTIAL_LENGTH).fill(''));
                      setCrackError(null);
                    }}
                    className="flex-1 px-3 py-2 text-xs rounded-lg border border-border-strong text-text-secondary hover:bg-elevated transition-colors"
                  >
                    Back
                  </button>
                  <button
                    type="button"
                    onClick={handleStartPartialCrack}
                    disabled={numUnknown === 0}
                    className="flex-1 px-3 py-2 text-xs rounded-lg bg-accent text-white hover:bg-[var(--accent-hover)] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    Search
                  </button>
                </div>
              </div>
            ) : (
              <>
                <p className="text-xs text-text-tertiary mb-2">
                  Forgot the password? Try every numeric passcode instead:
                </p>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => handleCrack(4)}
                    disabled={loading}
                    className="flex-1 px-3 py-2 text-xs rounded-lg border border-border-strong text-text-secondary hover:bg-elevated transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    All 4-digit codes
                  </button>
                  <button
                    type="button"
                    onClick={() => handleCrack(6)}
                    disabled={loading}
                    className="flex-1 px-3 py-2 text-xs rounded-lg border border-border-strong text-text-secondary hover:bg-elevated transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    All 6-digit codes
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => { setCrackError(null); setShowPartial(true); }}
                  disabled={loading}
                  className="w-full mt-2 px-3 py-2 text-xs rounded-lg border border-border-strong text-text-secondary hover:bg-elevated transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  I know some of the 6 digits
                </button>
                {crackError && (
                  <div className="mt-2 text-xs text-apple-error">{crackError}</div>
                )}
              </>
            )}
            {crack && (
              <div>
                <div className="flex items-center justify-between text-xs text-text-secondary mb-1.5">
                  <span>Trying {crack.digits}-digit codes… {percent}%</span>
                  <button
                    type="button"
                    onClick={handleStopCrack}
                    className="text-apple-error hover:underline"
                  >
                    Stop
                  </button>
                </div>
                <div className="w-full h-1.5 bg-elevated rounded-full overflow-hidden">
                  <div
                    className="h-full bg-accent rounded-full transition-all duration-300"
                    style={{ width: `${Math.max(2, percent)}%` }}
                  />
                </div>
                <p className="text-[11px] text-text-tertiary mt-1.5">
                  {crack.tried.toLocaleString()} / {crack.total.toLocaleString()} tried
                  {crack.total >= 100_000 && ' · this can take a while'}
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
