rule TTP_XOR_QUAD_CurrentVersionRun_3775 {
  strings:
    $key_3775 = { 64 1a [2] 40 14 [2] 6b 38 [2] 45 1a [2] 51 01 [2] 5e 1b [2] 40 06 [2] 42 07 [2] 59 01 [2] 45 06 [2] 59 29 }

  condition:
    any of them
}