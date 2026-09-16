rule TTP_XOR_QUAD_CurrentVersionRun_adb4 {
  strings:
    $key_adb4 = { fe db [2] da d5 [2] f1 f9 [2] df db [2] cb c0 [2] c4 da [2] da c7 [2] d8 c6 [2] c3 c0 [2] df c7 [2] c3 e8 }

  condition:
    any of them
}