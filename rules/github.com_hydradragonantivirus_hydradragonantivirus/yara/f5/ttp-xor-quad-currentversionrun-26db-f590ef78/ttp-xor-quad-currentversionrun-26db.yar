rule TTP_XOR_QUAD_CurrentVersionRun_26db {
  strings:
    $key_26db = { 75 b4 [2] 51 ba [2] 7a 96 [2] 54 b4 [2] 40 af [2] 4f b5 [2] 51 a8 [2] 53 a9 [2] 48 af [2] 54 a8 [2] 48 87 }

  condition:
    any of them
}