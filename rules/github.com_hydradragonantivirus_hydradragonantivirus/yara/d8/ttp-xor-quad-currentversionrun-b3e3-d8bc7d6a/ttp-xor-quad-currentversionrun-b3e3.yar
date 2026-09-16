rule TTP_XOR_QUAD_CurrentVersionRun_b3e3 {
  strings:
    $key_b3e3 = { e0 8c [2] c4 82 [2] ef ae [2] c1 8c [2] d5 97 [2] da 8d [2] c4 90 [2] c6 91 [2] dd 97 [2] c1 90 [2] dd bf }

  condition:
    any of them
}