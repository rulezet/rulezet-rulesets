rule TTP_XOR_QUAD_CurrentVersionRun_b008 {
  strings:
    $key_b008 = { e3 67 [2] c7 69 [2] ec 45 [2] c2 67 [2] d6 7c [2] d9 66 [2] c7 7b [2] c5 7a [2] de 7c [2] c2 7b [2] de 54 }

  condition:
    any of them
}