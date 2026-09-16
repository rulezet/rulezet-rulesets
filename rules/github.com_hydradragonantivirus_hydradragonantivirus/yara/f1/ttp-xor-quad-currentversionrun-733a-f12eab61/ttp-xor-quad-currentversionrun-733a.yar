rule TTP_XOR_QUAD_CurrentVersionRun_733a {
  strings:
    $key_733a = { 20 55 [2] 04 5b [2] 2f 77 [2] 01 55 [2] 15 4e [2] 1a 54 [2] 04 49 [2] 06 48 [2] 1d 4e [2] 01 49 [2] 1d 66 }

  condition:
    any of them
}