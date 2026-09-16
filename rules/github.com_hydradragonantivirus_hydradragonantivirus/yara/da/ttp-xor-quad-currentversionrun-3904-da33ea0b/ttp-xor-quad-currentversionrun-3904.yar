rule TTP_XOR_QUAD_CurrentVersionRun_3904 {
  strings:
    $key_3904 = { 6a 6b [2] 4e 65 [2] 65 49 [2] 4b 6b [2] 5f 70 [2] 50 6a [2] 4e 77 [2] 4c 76 [2] 57 70 [2] 4b 77 [2] 57 58 }

  condition:
    any of them
}