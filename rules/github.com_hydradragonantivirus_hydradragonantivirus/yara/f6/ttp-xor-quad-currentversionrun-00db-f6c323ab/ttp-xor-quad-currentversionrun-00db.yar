rule TTP_XOR_QUAD_CurrentVersionRun_00db {
  strings:
    $key_00db = { 53 b4 [2] 77 ba [2] 5c 96 [2] 72 b4 [2] 66 af [2] 69 b5 [2] 77 a8 [2] 75 a9 [2] 6e af [2] 72 a8 [2] 6e 87 }

  condition:
    any of them
}