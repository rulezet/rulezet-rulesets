rule TTP_XOR_QUAD_CurrentVersionRun_8bcd {
  strings:
    $key_8bcd = { d8 a2 [2] fc ac [2] d7 80 [2] f9 a2 [2] ed b9 [2] e2 a3 [2] fc be [2] fe bf [2] e5 b9 [2] f9 be [2] e5 91 }

  condition:
    any of them
}