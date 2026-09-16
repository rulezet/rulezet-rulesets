rule TTP_XOR_QUAD_CurrentVersionRun_f3d0 {
  strings:
    $key_f3d0 = { a0 bf [2] 84 b1 [2] af 9d [2] 81 bf [2] 95 a4 [2] 9a be [2] 84 a3 [2] 86 a2 [2] 9d a4 [2] 81 a3 [2] 9d 8c }

  condition:
    any of them
}