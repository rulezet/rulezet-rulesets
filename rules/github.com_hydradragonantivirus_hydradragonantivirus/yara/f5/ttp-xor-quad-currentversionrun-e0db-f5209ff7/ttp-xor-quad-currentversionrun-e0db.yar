rule TTP_XOR_QUAD_CurrentVersionRun_e0db {
  strings:
    $key_e0db = { b3 b4 [2] 97 ba [2] bc 96 [2] 92 b4 [2] 86 af [2] 89 b5 [2] 97 a8 [2] 95 a9 [2] 8e af [2] 92 a8 [2] 8e 87 }

  condition:
    any of them
}