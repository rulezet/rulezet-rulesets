rule TTP_XOR_QUAD_CurrentVersionRun_ecc8 {
  strings:
    $key_ecc8 = { bf a7 [2] 9b a9 [2] b0 85 [2] 9e a7 [2] 8a bc [2] 85 a6 [2] 9b bb [2] 99 ba [2] 82 bc [2] 9e bb [2] 82 94 }

  condition:
    any of them
}