rule TTP_XOR_QUAD_CurrentVersionRun_6204 {
  strings:
    $key_6204 = { 31 6b [2] 15 65 [2] 3e 49 [2] 10 6b [2] 04 70 [2] 0b 6a [2] 15 77 [2] 17 76 [2] 0c 70 [2] 10 77 [2] 0c 58 }

  condition:
    any of them
}