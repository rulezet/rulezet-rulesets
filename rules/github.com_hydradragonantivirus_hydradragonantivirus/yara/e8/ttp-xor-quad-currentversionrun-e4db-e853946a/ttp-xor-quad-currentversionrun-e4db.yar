rule TTP_XOR_QUAD_CurrentVersionRun_e4db {
  strings:
    $key_e4db = { b7 b4 [2] 93 ba [2] b8 96 [2] 96 b4 [2] 82 af [2] 8d b5 [2] 93 a8 [2] 91 a9 [2] 8a af [2] 96 a8 [2] 8a 87 }

  condition:
    any of them
}