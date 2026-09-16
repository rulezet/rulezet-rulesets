rule TTP_XOR_QUAD_CurrentVersionRun_b418 {
  strings:
    $key_b418 = { e7 77 [2] c3 79 [2] e8 55 [2] c6 77 [2] d2 6c [2] dd 76 [2] c3 6b [2] c1 6a [2] da 6c [2] c6 6b [2] da 44 }

  condition:
    any of them
}