rule TTP_XOR_QUAD_CurrentVersionRun_23c1 {
  strings:
    $key_23c1 = { 70 ae [2] 54 a0 [2] 7f 8c [2] 51 ae [2] 45 b5 [2] 4a af [2] 54 b2 [2] 56 b3 [2] 4d b5 [2] 51 b2 [2] 4d 9d }

  condition:
    any of them
}