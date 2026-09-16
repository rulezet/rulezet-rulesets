rule TTP_XOR_QUAD_CurrentVersionRun_b60c {
  strings:
    $key_b60c = { e5 63 [2] c1 6d [2] ea 41 [2] c4 63 [2] d0 78 [2] df 62 [2] c1 7f [2] c3 7e [2] d8 78 [2] c4 7f [2] d8 50 }

  condition:
    any of them
}