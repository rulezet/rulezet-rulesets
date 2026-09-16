rule TTP_XOR_QUAD_CurrentVersionRun_b044 {
  strings:
    $key_b044 = { e3 2b [2] c7 25 [2] ec 09 [2] c2 2b [2] d6 30 [2] d9 2a [2] c7 37 [2] c5 36 [2] de 30 [2] c2 37 [2] de 18 }

  condition:
    any of them
}