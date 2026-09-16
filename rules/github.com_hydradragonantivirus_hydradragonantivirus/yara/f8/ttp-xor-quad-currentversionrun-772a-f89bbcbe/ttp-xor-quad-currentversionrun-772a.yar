rule TTP_XOR_QUAD_CurrentVersionRun_772a {
  strings:
    $key_772a = { 24 45 [2] 00 4b [2] 2b 67 [2] 05 45 [2] 11 5e [2] 1e 44 [2] 00 59 [2] 02 58 [2] 19 5e [2] 05 59 [2] 19 76 }

  condition:
    any of them
}