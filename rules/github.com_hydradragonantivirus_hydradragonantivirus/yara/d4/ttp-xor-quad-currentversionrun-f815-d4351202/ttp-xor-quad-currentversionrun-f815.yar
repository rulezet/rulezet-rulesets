rule TTP_XOR_QUAD_CurrentVersionRun_f815 {
  strings:
    $key_f815 = { ab 7a [2] 8f 74 [2] a4 58 [2] 8a 7a [2] 9e 61 [2] 91 7b [2] 8f 66 [2] 8d 67 [2] 96 61 [2] 8a 66 [2] 96 49 }

  condition:
    any of them
}