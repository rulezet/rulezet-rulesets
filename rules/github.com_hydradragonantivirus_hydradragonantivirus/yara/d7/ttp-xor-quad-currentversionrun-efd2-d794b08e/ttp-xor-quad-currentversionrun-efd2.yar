rule TTP_XOR_QUAD_CurrentVersionRun_efd2 {
  strings:
    $key_efd2 = { bc bd [2] 98 b3 [2] b3 9f [2] 9d bd [2] 89 a6 [2] 86 bc [2] 98 a1 [2] 9a a0 [2] 81 a6 [2] 9d a1 [2] 81 8e }

  condition:
    any of them
}