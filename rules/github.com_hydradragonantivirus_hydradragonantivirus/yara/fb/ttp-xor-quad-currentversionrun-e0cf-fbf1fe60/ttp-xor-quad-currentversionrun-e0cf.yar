rule TTP_XOR_QUAD_CurrentVersionRun_e0cf {
  strings:
    $key_e0cf = { b3 a0 [2] 97 ae [2] bc 82 [2] 92 a0 [2] 86 bb [2] 89 a1 [2] 97 bc [2] 95 bd [2] 8e bb [2] 92 bc [2] 8e 93 }

  condition:
    any of them
}