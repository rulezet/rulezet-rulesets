rule TTP_XOR_QUAD_CurrentVersionRun_11dd {
  strings:
    $key_11dd = { 42 b2 [2] 66 bc [2] 4d 90 [2] 63 b2 [2] 77 a9 [2] 78 b3 [2] 66 ae [2] 64 af [2] 7f a9 [2] 63 ae [2] 7f 81 }

  condition:
    any of them
}