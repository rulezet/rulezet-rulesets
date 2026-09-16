rule TTP_XOR_QUAD_CurrentVersionRun_0a47 {
  strings:
    $key_0a47 = { 59 28 [2] 7d 26 [2] 56 0a [2] 78 28 [2] 6c 33 [2] 63 29 [2] 7d 34 [2] 7f 35 [2] 64 33 [2] 78 34 [2] 64 1b }

  condition:
    any of them
}