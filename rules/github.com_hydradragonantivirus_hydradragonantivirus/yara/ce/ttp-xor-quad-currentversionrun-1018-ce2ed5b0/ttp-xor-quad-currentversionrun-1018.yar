rule TTP_XOR_QUAD_CurrentVersionRun_1018 {
  strings:
    $key_1018 = { 43 77 [2] 67 79 [2] 4c 55 [2] 62 77 [2] 76 6c [2] 79 76 [2] 67 6b [2] 65 6a [2] 7e 6c [2] 62 6b [2] 7e 44 }

  condition:
    any of them
}