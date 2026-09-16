rule TTP_XOR_QUAD_CurrentVersionRun_adb7 {
  strings:
    $key_adb7 = { fe d8 [2] da d6 [2] f1 fa [2] df d8 [2] cb c3 [2] c4 d9 [2] da c4 [2] d8 c5 [2] c3 c3 [2] df c4 [2] c3 eb }

  condition:
    any of them
}