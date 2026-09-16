rule TTP_XOR_QUAD_CurrentVersionRun_75d0 {
  strings:
    $key_75d0 = { 26 bf [2] 02 b1 [2] 29 9d [2] 07 bf [2] 13 a4 [2] 1c be [2] 02 a3 [2] 00 a2 [2] 1b a4 [2] 07 a3 [2] 1b 8c }

  condition:
    any of them
}