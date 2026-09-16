rule TTP_XOR_QUAD_CurrentVersionRun_11d0 {
  strings:
    $key_11d0 = { 42 bf [2] 66 b1 [2] 4d 9d [2] 63 bf [2] 77 a4 [2] 78 be [2] 66 a3 [2] 64 a2 [2] 7f a4 [2] 63 a3 [2] 7f 8c }

  condition:
    any of them
}