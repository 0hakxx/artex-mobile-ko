/*
 * 계측 자가검증 (instrumentation self-test). ios_checks.js 의 후킹이 실기기에서
 * 실제로 트리거되는지, 무해한 입력을 '내가' 호출해 확인한다 (앱 동작 분석 아님).
 * DVIA 같은 취약 앱이 설치되면 동일 후킹이 '앱의' 실제 호출을 잡는다.
 */
'use strict';
function report(o) { send(Object.assign({ _artex: true }, o)); }

if (!ObjC.available) { report({ check: 'env', severity: 'info', title: 'ObjC 불가' }); }
else {
  // --- 후킹: 탈옥탐지(fileExistsAtPath) + NSUserDefaults 평문 저장 ---
  try {
    var FM = ObjC.classes.NSFileManager['- fileExistsAtPath:'];
    Interceptor.attach(FM.implementation, {
      onEnter: function (a) {
        try {
          var p = new ObjC.Object(a[2]).toString();
          if (/Cydia|apt|ssh|MobileSubstrate|frida|\/bin\/sh/i.test(p))
            report({ check: 'jailbreak_detection', mastg: 'MASTG-TEST-0063', masvs: 'MASVS-RESILIENCE-1',
                     severity: 'medium', title: '탈옥 탐지로 보이는 파일 존재 확인',
                     evidence: 'fileExistsAtPath:"' + p + '"' });
        } catch (e) {}
      }
    });
    var UD = ObjC.classes.NSUserDefaults['- setObject:forKey:'];
    Interceptor.attach(UD.implementation, {
      onEnter: function (a) {
        try {
          var k = new ObjC.Object(a[3]).toString();
          report({ check: 'userdefaults_write', mastg: 'MASTG-TEST-0052', masvs: 'MASVS-STORAGE-1',
                   severity: 'low', title: 'NSUserDefaults 평문 저장(민감정보 가능)',
                   evidence: 'setObject:forKey:"' + k + '"' });
        } catch (e) {}
      }
    });
  } catch (e) { report({ check: 'hook_err', severity: 'info', title: '후킹 실패', evidence: '' + e }); }

  // --- 무해한 트리거: 내가 호출해 후킹이 잡는지 검증 ---
  setTimeout(function () {
    try {
      ObjC.classes.NSFileManager.defaultManager().fileExistsAtPath_('/Applications/Cydia.app');
      var d = ObjC.classes.NSUserDefaults.standardUserDefaults();
      d.setObject_forKey_(ObjC.classes.NSString.stringWithString_('artex'),
                          ObjC.classes.NSString.stringWithString_('artex_selftest'));
      report({ check: 'hooks_installed', severity: 'info', title: '자가검증 트리거 완료', evidence: 'ios_selftest.js' });
    } catch (e) { report({ check: 'trigger_err', severity: 'info', title: '트리거 실패', evidence: '' + e }); }
  }, 1200);
}
