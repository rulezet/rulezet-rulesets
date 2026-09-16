rule TTP_XOR_QUAD_CurrentVersionRun_b006 {
  strings:
    $key_b006 = { e3 69 [2] c7 67 [2] ec 4b [2] c2 69 [2] d6 72 [2] d9 68 [2] c7 75 [2] c5 74 [2] de 72 [2] c2 75 [2] de 5a }

  condition:
    any of them
}