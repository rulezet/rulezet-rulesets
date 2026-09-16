rule TTP_XOR_QUAD_CurrentVersionRun_b07a {
  strings:
    $key_b07a = { e3 15 [2] c7 1b [2] ec 37 [2] c2 15 [2] d6 0e [2] d9 14 [2] c7 09 [2] c5 08 [2] de 0e [2] c2 09 [2] de 26 }

  condition:
    any of them
}