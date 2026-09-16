rule TTP_XOR_QUAD_CurrentVersionRun_f3db {
  strings:
    $key_f3db = { a0 b4 [2] 84 ba [2] af 96 [2] 81 b4 [2] 95 af [2] 9a b5 [2] 84 a8 [2] 86 a9 [2] 9d af [2] 81 a8 [2] 9d 87 }

  condition:
    any of them
}