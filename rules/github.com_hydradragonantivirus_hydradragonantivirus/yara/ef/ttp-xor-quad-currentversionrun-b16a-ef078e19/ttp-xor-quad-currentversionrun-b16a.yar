rule TTP_XOR_QUAD_CurrentVersionRun_b16a {
  strings:
    $key_b16a = { e2 05 [2] c6 0b [2] ed 27 [2] c3 05 [2] d7 1e [2] d8 04 [2] c6 19 [2] c4 18 [2] df 1e [2] c3 19 [2] df 36 }

  condition:
    any of them
}