rule TTP_XOR_QUAD_CurrentVersionRun_b011 {
  strings:
    $key_b011 = { e3 7e [2] c7 70 [2] ec 5c [2] c2 7e [2] d6 65 [2] d9 7f [2] c7 62 [2] c5 63 [2] de 65 [2] c2 62 [2] de 4d }

  condition:
    any of them
}