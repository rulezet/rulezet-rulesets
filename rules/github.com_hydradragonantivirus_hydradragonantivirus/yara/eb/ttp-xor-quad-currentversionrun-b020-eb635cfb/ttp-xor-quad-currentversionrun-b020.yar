rule TTP_XOR_QUAD_CurrentVersionRun_b020 {
  strings:
    $key_b020 = { e3 4f [2] c7 41 [2] ec 6d [2] c2 4f [2] d6 54 [2] d9 4e [2] c7 53 [2] c5 52 [2] de 54 [2] c2 53 [2] de 7c }

  condition:
    any of them
}