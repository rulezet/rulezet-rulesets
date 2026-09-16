rule TTP_XOR_QUAD_CurrentVersionRun_3774 {
  strings:
    $key_3774 = { 64 1b [2] 40 15 [2] 6b 39 [2] 45 1b [2] 51 00 [2] 5e 1a [2] 40 07 [2] 42 06 [2] 59 00 [2] 45 07 [2] 59 28 }

  condition:
    any of them
}