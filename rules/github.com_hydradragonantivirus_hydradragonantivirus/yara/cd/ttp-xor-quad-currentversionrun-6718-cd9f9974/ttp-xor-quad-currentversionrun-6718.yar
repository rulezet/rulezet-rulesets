rule TTP_XOR_QUAD_CurrentVersionRun_6718 {
  strings:
    $key_6718 = { 34 77 [2] 10 79 [2] 3b 55 [2] 15 77 [2] 01 6c [2] 0e 76 [2] 10 6b [2] 12 6a [2] 09 6c [2] 15 6b [2] 09 44 }

  condition:
    any of them
}