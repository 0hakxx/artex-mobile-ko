/*
 * Mobile ARTEX — Android 런타임 점검 (§9-3). Frida 스크립트.
 * MASTG 항목별 후킹: SSL 피닝, 루팅 탐지, 약한 암호 API, 클립보드/로그 누출.
 *
 * send({check, mastg, masvs, severity, title, evidence}) 로 호스트에 구조화 보고.
 * 호스트(frida_adapter)가 이 메시지를 모아 dynamic findings 로 변환(confidence=confirmed).
 */
'use strict';

function report(o) { send(Object.assign({ _artex: true }, o)); }

if (!Java.available) {
  report({ check: 'env', severity: 'info', title: 'Java 런타임 불가', evidence: 'Java.available=false' });
} else {
  Java.perform(function () {

    // --- 1) SSL 피닝 / 인증서 검증 우회 가능성 (MASVS-NETWORK) ---
    try {
      var TMI = Java.use('javax.net.ssl.X509TrustManager');
      var SSLCtx = Java.use('javax.net.ssl.SSLContext');
      var init = SSLCtx.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
      init.implementation = function (km, tm, sr) {
        report({ check: 'ssl_trustmanager_init', mastg: 'MASTG-TEST-0019', masvs: 'MASVS-NETWORK-1',
                 severity: 'high', title: 'SSLContext.init 후킹됨 — 커스텀 TrustManager 주입 가능',
                 evidence: 'SSLContext.init() 호출 가로채기 성공 → 핀닝 우회 표면 존재' });
        return init.call(this, km, tm, sr);
      };
    } catch (e) { report({ check: 'ssl_hook_err', severity: 'info', title: 'SSL 후킹 실패', evidence: '' + e }); }

    // --- 2) 루팅 탐지 로직 존재 여부 (MASVS-RESILIENCE) ---
    try {
      var Runtime = Java.use('java.lang.Runtime');
      Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd && (cmd.indexOf('su') >= 0 || cmd.indexOf('which') >= 0)) {
          report({ check: 'root_detection_exec', mastg: 'MASTG-TEST-0049', masvs: 'MASVS-RESILIENCE-1',
                   severity: 'medium', title: '루팅 탐지로 보이는 명령 실행',
                   evidence: 'Runtime.exec("' + cmd + '")' });
        }
        return this.exec(cmd);
      };
    } catch (e) {}

    // --- 3) 약한 암호/해시 API 런타임 사용 (MASVS-CRYPTO) ---
    try {
      var MD = Java.use('java.security.MessageDigest');
      MD.getInstance.overload('java.lang.String').implementation = function (algo) {
        if (algo && /MD5|SHA-?1/i.test(algo)) {
          report({ check: 'weak_hash_runtime', mastg: 'MASTG-TEST-0203', masvs: 'MASVS-CRYPTO-1',
                   severity: 'medium', title: '런타임에서 약한 해시 사용: ' + algo,
                   evidence: 'MessageDigest.getInstance("' + algo + '")' });
        }
        return this.getInstance(algo);
      };
      var Cipher = Java.use('javax.crypto.Cipher');
      Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
        if (t && /ECB|^DES/i.test(t)) {
          report({ check: 'weak_cipher_runtime', mastg: 'MASTG-TEST-0221', masvs: 'MASVS-CRYPTO-2',
                   severity: 'high', title: '런타임에서 취약 암호 구성: ' + t,
                   evidence: 'Cipher.getInstance("' + t + '")' });
        }
        return this.getInstance(t);
      };
    } catch (e) {}

    // --- 4) 클립보드 / 로그 민감정보 누출 (MASVS-PLATFORM/STORAGE) ---
    try {
      var Log = Java.use('android.util.Log');
      ['d', 'v', 'i'].forEach(function (m) {
        Log[m].overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
          if (msg && msg.length > 0) {
            report({ check: 'runtime_logging', mastg: 'MASTG-TEST-0003', masvs: 'MASVS-STORAGE-2',
                     severity: 'low', title: '런타임 로그 출력(민감정보 가능)',
                     evidence: 'Log.' + m + '("' + tag + '", "' + ('' + msg).slice(0, 80) + '")' });
          }
          return this[m](tag, msg);
        };
      });
    } catch (e) {}

    report({ check: 'hooks_installed', severity: 'info', title: '동적 후킹 설치 완료', evidence: 'android_checks.js' });
  });
}
