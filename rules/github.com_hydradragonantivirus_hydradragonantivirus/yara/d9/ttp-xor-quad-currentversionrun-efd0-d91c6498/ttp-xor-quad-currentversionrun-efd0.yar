rule TTP_XOR_QUAD_CurrentVersionRun_efd0 {
  strings:
    $key_efd0 = { bc bf [2] 98 b1 [2] b3 9d [2] 9d bf [2] 89 a4 [2] 86 be [2] 98 a3 [2] 9a a2 [2] 81 a4 [2] 9d a3 [2] 81 8c }

  condition:
    any of them
}