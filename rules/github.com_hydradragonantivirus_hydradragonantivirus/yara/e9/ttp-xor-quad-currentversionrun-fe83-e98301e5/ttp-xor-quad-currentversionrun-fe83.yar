rule TTP_XOR_QUAD_CurrentVersionRun_fe83 {
  strings:
    $key_fe83 = { ad ec [2] 89 e2 [2] a2 ce [2] 8c ec [2] 98 f7 [2] 97 ed [2] 89 f0 [2] 8b f1 [2] 90 f7 [2] 8c f0 [2] 90 df }

  condition:
    any of them
}