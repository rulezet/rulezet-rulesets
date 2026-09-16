rule TTP_XOR_QUAD_CurrentVersionRun_b00d {
  strings:
    $key_b00d = { e3 62 [2] c7 6c [2] ec 40 [2] c2 62 [2] d6 79 [2] d9 63 [2] c7 7e [2] c5 7f [2] de 79 [2] c2 7e [2] de 51 }

  condition:
    any of them
}