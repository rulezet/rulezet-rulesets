rule TTP_XOR_QUAD_CurrentVersionRun_0a54 {
  strings:
    $key_0a54 = { 59 3b [2] 7d 35 [2] 56 19 [2] 78 3b [2] 6c 20 [2] 63 3a [2] 7d 27 [2] 7f 26 [2] 64 20 [2] 78 27 [2] 64 08 }

  condition:
    any of them
}