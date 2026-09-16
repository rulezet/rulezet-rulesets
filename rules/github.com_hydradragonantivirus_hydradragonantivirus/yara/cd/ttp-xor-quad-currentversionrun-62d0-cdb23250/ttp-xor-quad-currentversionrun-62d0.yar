rule TTP_XOR_QUAD_CurrentVersionRun_62d0 {
  strings:
    $key_62d0 = { 31 bf [2] 15 b1 [2] 3e 9d [2] 10 bf [2] 04 a4 [2] 0b be [2] 15 a3 [2] 17 a2 [2] 0c a4 [2] 10 a3 [2] 0c 8c }

  condition:
    any of them
}