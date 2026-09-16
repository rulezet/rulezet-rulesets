rule TTP_XOR_QUAD_CurrentVersionRun_8bc0 {
  strings:
    $key_8bc0 = { d8 af [2] fc a1 [2] d7 8d [2] f9 af [2] ed b4 [2] e2 ae [2] fc b3 [2] fe b2 [2] e5 b4 [2] f9 b3 [2] e5 9c }

  condition:
    any of them
}