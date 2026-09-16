rule TTP_XOR_QUAD_CurrentVersionRun_3769 {
  strings:
    $key_3769 = { 64 06 [2] 40 08 [2] 6b 24 [2] 45 06 [2] 51 1d [2] 5e 07 [2] 40 1a [2] 42 1b [2] 59 1d [2] 45 1a [2] 59 35 }

  condition:
    any of them
}