rule TTP_XOR_QUAD_CurrentVersionRun_50db {
  strings:
    $key_50db = { 03 b4 [2] 27 ba [2] 0c 96 [2] 22 b4 [2] 36 af [2] 39 b5 [2] 27 a8 [2] 25 a9 [2] 3e af [2] 22 a8 [2] 3e 87 }

  condition:
    any of them
}