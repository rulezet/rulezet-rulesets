rule TTP_XOR_QUAD_CurrentVersionRun_eda8 {
  strings:
    $key_eda8 = { be c7 [2] 9a c9 [2] b1 e5 [2] 9f c7 [2] 8b dc [2] 84 c6 [2] 9a db [2] 98 da [2] 83 dc [2] 9f db [2] 83 f4 }

  condition:
    any of them
}