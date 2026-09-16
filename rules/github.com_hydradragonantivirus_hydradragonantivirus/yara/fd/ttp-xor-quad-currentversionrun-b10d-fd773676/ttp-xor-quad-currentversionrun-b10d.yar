rule TTP_XOR_QUAD_CurrentVersionRun_b10d {
  strings:
    $key_b10d = { e2 62 [2] c6 6c [2] ed 40 [2] c3 62 [2] d7 79 [2] d8 63 [2] c6 7e [2] c4 7f [2] df 79 [2] c3 7e [2] df 51 }

  condition:
    any of them
}