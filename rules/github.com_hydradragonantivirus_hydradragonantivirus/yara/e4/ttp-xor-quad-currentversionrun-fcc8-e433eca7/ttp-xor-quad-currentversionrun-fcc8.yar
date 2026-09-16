rule TTP_XOR_QUAD_CurrentVersionRun_fcc8 {
  strings:
    $key_fcc8 = { af a7 [2] 8b a9 [2] a0 85 [2] 8e a7 [2] 9a bc [2] 95 a6 [2] 8b bb [2] 89 ba [2] 92 bc [2] 8e bb [2] 92 94 }

  condition:
    any of them
}