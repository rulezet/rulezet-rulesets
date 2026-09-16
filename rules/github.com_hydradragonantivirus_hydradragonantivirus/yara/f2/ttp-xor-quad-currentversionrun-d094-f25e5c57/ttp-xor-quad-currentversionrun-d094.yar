rule TTP_XOR_QUAD_CurrentVersionRun_d094 {
  strings:
    $key_d094 = { 83 fb [2] a7 f5 [2] 8c d9 [2] a2 fb [2] b6 e0 [2] b9 fa [2] a7 e7 [2] a5 e6 [2] be e0 [2] a2 e7 [2] be c8 }

  condition:
    any of them
}