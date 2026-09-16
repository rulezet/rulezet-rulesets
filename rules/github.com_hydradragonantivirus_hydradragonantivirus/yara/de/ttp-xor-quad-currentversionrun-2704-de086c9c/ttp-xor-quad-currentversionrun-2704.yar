rule TTP_XOR_QUAD_CurrentVersionRun_2704 {
  strings:
    $key_2704 = { 74 6b [2] 50 65 [2] 7b 49 [2] 55 6b [2] 41 70 [2] 4e 6a [2] 50 77 [2] 52 76 [2] 49 70 [2] 55 77 [2] 49 58 }

  condition:
    any of them
}