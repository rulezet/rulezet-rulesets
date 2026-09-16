rule TTP_XOR_QUAD_CurrentVersionRun_b060 {
  strings:
    $key_b060 = { e3 0f [2] c7 01 [2] ec 2d [2] c2 0f [2] d6 14 [2] d9 0e [2] c7 13 [2] c5 12 [2] de 14 [2] c2 13 [2] de 3c }

  condition:
    any of them
}