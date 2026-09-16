rule TTP_XOR_QUAD_CurrentVersionRun_b13f {
  strings:
    $key_b13f = { e2 50 [2] c6 5e [2] ed 72 [2] c3 50 [2] d7 4b [2] d8 51 [2] c6 4c [2] c4 4d [2] df 4b [2] c3 4c [2] df 63 }

  condition:
    any of them
}