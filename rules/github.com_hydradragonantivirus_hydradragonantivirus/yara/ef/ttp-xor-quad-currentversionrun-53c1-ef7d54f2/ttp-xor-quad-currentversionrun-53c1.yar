rule TTP_XOR_QUAD_CurrentVersionRun_53c1 {
  strings:
    $key_53c1 = { 00 ae [2] 24 a0 [2] 0f 8c [2] 21 ae [2] 35 b5 [2] 3a af [2] 24 b2 [2] 26 b3 [2] 3d b5 [2] 21 b2 [2] 3d 9d }

  condition:
    any of them
}