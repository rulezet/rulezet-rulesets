rule TTP_XOR_QUAD_CurrentVersionRun_33c1 {
  strings:
    $key_33c1 = { 60 ae [2] 44 a0 [2] 6f 8c [2] 41 ae [2] 55 b5 [2] 5a af [2] 44 b2 [2] 46 b3 [2] 5d b5 [2] 41 b2 [2] 5d 9d }

  condition:
    any of them
}