rule TTP_XOR_QUAD_CurrentVersionRun_eac8 {
  strings:
    $key_eac8 = { b9 a7 [2] 9d a9 [2] b6 85 [2] 98 a7 [2] 8c bc [2] 83 a6 [2] 9d bb [2] 9f ba [2] 84 bc [2] 98 bb [2] 84 94 }

  condition:
    any of them
}