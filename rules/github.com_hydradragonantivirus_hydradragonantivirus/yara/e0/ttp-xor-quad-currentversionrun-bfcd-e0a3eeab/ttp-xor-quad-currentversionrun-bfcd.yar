rule TTP_XOR_QUAD_CurrentVersionRun_bfcd {
  strings:
    $key_bfcd = { ec a2 [2] c8 ac [2] e3 80 [2] cd a2 [2] d9 b9 [2] d6 a3 [2] c8 be [2] ca bf [2] d1 b9 [2] cd be [2] d1 91 }

  condition:
    any of them
}