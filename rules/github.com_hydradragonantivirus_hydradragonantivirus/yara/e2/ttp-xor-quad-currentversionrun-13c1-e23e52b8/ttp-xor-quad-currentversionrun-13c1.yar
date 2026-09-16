rule TTP_XOR_QUAD_CurrentVersionRun_13c1 {
  strings:
    $key_13c1 = { 40 ae [2] 64 a0 [2] 4f 8c [2] 61 ae [2] 75 b5 [2] 7a af [2] 64 b2 [2] 66 b3 [2] 7d b5 [2] 61 b2 [2] 7d 9d }

  condition:
    any of them
}