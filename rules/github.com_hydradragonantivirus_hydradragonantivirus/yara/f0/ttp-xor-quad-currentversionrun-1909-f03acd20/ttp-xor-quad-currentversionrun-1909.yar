rule TTP_XOR_QUAD_CurrentVersionRun_1909 {
  strings:
    $key_1909 = { 4a 66 [2] 6e 68 [2] 45 44 [2] 6b 66 [2] 7f 7d [2] 70 67 [2] 6e 7a [2] 6c 7b [2] 77 7d [2] 6b 7a [2] 77 55 }

  condition:
    any of them
}