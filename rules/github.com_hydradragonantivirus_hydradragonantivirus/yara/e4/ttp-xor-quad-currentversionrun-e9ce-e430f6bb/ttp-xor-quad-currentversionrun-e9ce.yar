rule TTP_XOR_QUAD_CurrentVersionRun_e9ce {
  strings:
    $key_e9ce = { ba a1 [2] 9e af [2] b5 83 [2] 9b a1 [2] 8f ba [2] 80 a0 [2] 9e bd [2] 9c bc [2] 87 ba [2] 9b bd [2] 87 92 }

  condition:
    any of them
}