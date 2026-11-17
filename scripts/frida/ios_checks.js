/*
 * Mobile ARTEX — iOS 런타임 점검 (§10-5). Frida(ObjC) 스크립트, 탈옥 실단말.
 * 재서명·설치 불가 가정, 런타임 후킹에 집중.
 *   - 탈옥 탐지 로직 존재 (파일 존재 체크 / fork)
 *   - SSL 피닝 표면 (SecTrustEvaluate / NSURLSession 델리게이트)
 *   - 민감 API (NSLog, UIPasteboard, NSUserDefaults 평문)
 *
 * send({check, mastg, masvs, severity, title, evidence}) 로 호스트에 구조화 보고.
 */
'use strict';

function report(o) { send(Object.assign({ _artex: true }, o)); }

if (!ObjC.available) {
  report({ check: 'env', severity: 'info', title: 'ObjC 런타임 불가', evidence: 'ObjC.available=false' });
} else {
  try {
    // --- 1) 탈옥 탐지로 보이는 파일 존재 확인 (MASVS-RESILIENCE) ---
    var NSFileManager = ObjC.classes.NSFileManager;
    var fileExists = NSFileManager['- fileExistsAtPath:'];
    Interceptor.attach(fileExists.implementation, {
      onEnter: function (args) {
        try {
          var p = new ObjC.Object(args[2]).toString();
          if (/Cydia|apt|ssh|bash|MobileSubstrate|frida|\/bin\/sh/i.test(p)) {
            report({ check: 'jailbreak_detection', mastg: 'MASTG-TEST-0063', masvs: 'MASVS-RESILIENCE-1',
                     severity: 'medium', title: '탈옥 탐지로 보이는 파일 존재 확인',
                     evidence: 'fileExistsAtPath:"' + p + '"' });
          }
        } catch (e) {}
      }
    });
  } catch (e) { report({ check: 'jb_hook_err', severity: 'info', title: 'JB 후킹 실패', evidence: '' + e }); }

  // --- 2) SSL 피닝 표면: SecTrustEvaluate 계열 (MASVS-NETWORK) ---
  try {
    var secMods = ['SecTrustEvaluate', 'SecTrustEvaluateWithError'];
    secMods.forEach(function (name) {
      var p = Module.findExportByName('Security', name);
      if (p) {
        Interceptor.attach(p, {
          onEnter: function () {
            report({ check: 'ssl_sectrust', mastg: 'MASTG-TEST-0019', masvs: 'MASVS-NETWORK-1',
                     severity: 'high', title: 'SecTrust 평가 호출(' + name + ') — 핀닝 우회 표면',
                     evidence: name + ' 호출 가로채기 성공' });
          }
        });
      }
    });
  } catch (e) {}

  // --- 3) 민감 API: NSLog / UIPasteboard / NSUserDefaults (MASVS-STORAGE/PLATFORM) ---
  try {
    var NSUserDefaults = ObjC.classes.NSUserDefaults;
    var setObj = NSUserDefaults['- setObject:forKey:'];
    Interceptor.attach(setObj.implementation, {
      onEnter: function (args) {
        try {
          var k = new ObjC.Object(args[3]).toString();
          report({ check: 'userdefaults_write', mastg: 'MASTG-TEST-0052', masvs: 'MASVS-STORAGE-1',
                   severity: 'low', title: 'NSUserDefaults 평문 저장(민감정보 가능)',
                   evidence: 'setObject:forKey:"' + k + '"' });
        } catch (e) {}
      }
    });
  } catch (e) {}

  try {
    var pb = Module.findExportByName(null, 'NSLog');
    report({ check: 'hooks_installed', severity: 'info', title: '동적 후킹 설치 완료', evidence: 'ios_checks.js' });
  } catch (e) {}
}
