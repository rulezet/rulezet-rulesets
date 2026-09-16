rule TTP_XOR_QUAD_CurrentVersionRun_b17e {
  strings:
    $key_b17e = { e2 11 [2] c6 1f [2] ed 33 [2] c3 11 [2] d7 0a [2] d8 10 [2] c6 0d [2] c4 0c [2] df 0a [2] c3 0d [2] df 22 }

  condition:
    any of them
}