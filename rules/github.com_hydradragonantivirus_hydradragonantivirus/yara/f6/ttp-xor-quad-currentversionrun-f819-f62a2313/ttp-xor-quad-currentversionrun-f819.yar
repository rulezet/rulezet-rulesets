rule TTP_XOR_QUAD_CurrentVersionRun_f819 {
  strings:
    $key_f819 = { ab 76 [2] 8f 78 [2] a4 54 [2] 8a 76 [2] 9e 6d [2] 91 77 [2] 8f 6a [2] 8d 6b [2] 96 6d [2] 8a 6a [2] 96 45 }

  condition:
    any of them
}