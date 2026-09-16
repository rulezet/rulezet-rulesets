rule TTP_XOR_QUAD_CurrentVersionRun_bbe8 {
  strings:
    $key_bbe8 = { e8 87 [2] cc 89 [2] e7 a5 [2] c9 87 [2] dd 9c [2] d2 86 [2] cc 9b [2] ce 9a [2] d5 9c [2] c9 9b [2] d5 b4 }

  condition:
    any of them
}