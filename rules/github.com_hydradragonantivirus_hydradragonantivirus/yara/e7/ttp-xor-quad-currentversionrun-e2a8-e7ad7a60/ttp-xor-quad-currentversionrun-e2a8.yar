rule TTP_XOR_QUAD_CurrentVersionRun_e2a8 {
  strings:
    $key_e2a8 = { b1 c7 [2] 95 c9 [2] be e5 [2] 90 c7 [2] 84 dc [2] 8b c6 [2] 95 db [2] 97 da [2] 8c dc [2] 90 db [2] 8c f4 }

  condition:
    any of them
}