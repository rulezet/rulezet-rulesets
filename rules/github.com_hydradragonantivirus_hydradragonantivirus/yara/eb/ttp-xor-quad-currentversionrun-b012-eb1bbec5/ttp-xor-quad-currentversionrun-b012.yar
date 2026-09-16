rule TTP_XOR_QUAD_CurrentVersionRun_b012 {
  strings:
    $key_b012 = { e3 7d [2] c7 73 [2] ec 5f [2] c2 7d [2] d6 66 [2] d9 7c [2] c7 61 [2] c5 60 [2] de 66 [2] c2 61 [2] de 4e }

  condition:
    any of them
}