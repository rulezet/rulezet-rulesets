rule TTP_XOR_QUAD_CurrentVersionRun_b029 {
  strings:
    $key_b029 = { e3 46 [2] c7 48 [2] ec 64 [2] c2 46 [2] d6 5d [2] d9 47 [2] c7 5a [2] c5 5b [2] de 5d [2] c2 5a [2] de 75 }

  condition:
    any of them
}