rule TTP_XOR_QUAD_CurrentVersionRun_b072 {
  strings:
    $key_b072 = { e3 1d [2] c7 13 [2] ec 3f [2] c2 1d [2] d6 06 [2] d9 1c [2] c7 01 [2] c5 00 [2] de 06 [2] c2 01 [2] de 2e }

  condition:
    any of them
}