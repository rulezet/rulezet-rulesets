rule TTP_XOR_QUAD_CurrentVersionRun_43db {
  strings:
    $key_43db = { 10 b4 [2] 34 ba [2] 1f 96 [2] 31 b4 [2] 25 af [2] 2a b5 [2] 34 a8 [2] 36 a9 [2] 2d af [2] 31 a8 [2] 2d 87 }

  condition:
    any of them
}