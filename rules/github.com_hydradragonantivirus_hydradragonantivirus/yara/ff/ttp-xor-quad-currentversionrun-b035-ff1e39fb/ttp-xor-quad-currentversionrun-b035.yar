rule TTP_XOR_QUAD_CurrentVersionRun_b035 {
  strings:
    $key_b035 = { e3 5a [2] c7 54 [2] ec 78 [2] c2 5a [2] d6 41 [2] d9 5b [2] c7 46 [2] c5 47 [2] de 41 [2] c2 46 [2] de 69 }

  condition:
    any of them
}