rule TTP_XOR_QUAD_CurrentVersionRun_1955 {
  strings:
    $key_1955 = { 4a 3a [2] 6e 34 [2] 45 18 [2] 6b 3a [2] 7f 21 [2] 70 3b [2] 6e 26 [2] 6c 27 [2] 77 21 [2] 6b 26 [2] 77 09 }

  condition:
    any of them
}