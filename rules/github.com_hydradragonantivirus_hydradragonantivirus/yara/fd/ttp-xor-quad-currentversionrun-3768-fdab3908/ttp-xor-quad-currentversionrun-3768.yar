rule TTP_XOR_QUAD_CurrentVersionRun_3768 {
  strings:
    $key_3768 = { 64 07 [2] 40 09 [2] 6b 25 [2] 45 07 [2] 51 1c [2] 5e 06 [2] 40 1b [2] 42 1a [2] 59 1c [2] 45 1b [2] 59 34 }

  condition:
    any of them
}