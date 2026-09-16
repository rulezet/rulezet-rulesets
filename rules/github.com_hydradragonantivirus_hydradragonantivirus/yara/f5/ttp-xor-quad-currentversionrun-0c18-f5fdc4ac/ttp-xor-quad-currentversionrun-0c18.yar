rule TTP_XOR_QUAD_CurrentVersionRun_0c18 {
  strings:
    $key_0c18 = { 5f 77 [2] 7b 79 [2] 50 55 [2] 7e 77 [2] 6a 6c [2] 65 76 [2] 7b 6b [2] 79 6a [2] 62 6c [2] 7e 6b [2] 62 44 }

  condition:
    any of them
}