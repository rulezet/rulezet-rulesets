rule TTP_XOR_QUAD_CurrentVersionRun_4adb {
  strings:
    $key_4adb = { 19 b4 [2] 3d ba [2] 16 96 [2] 38 b4 [2] 2c af [2] 23 b5 [2] 3d a8 [2] 3f a9 [2] 24 af [2] 38 a8 [2] 24 87 }

  condition:
    any of them
}