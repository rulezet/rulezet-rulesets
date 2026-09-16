rule TTP_XOR_QUAD_CurrentVersionRun_3755 {
  strings:
    $key_3755 = { 64 3a [2] 40 34 [2] 6b 18 [2] 45 3a [2] 51 21 [2] 5e 3b [2] 40 26 [2] 42 27 [2] 59 21 [2] 45 26 [2] 59 09 }

  condition:
    any of them
}