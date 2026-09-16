rule TTP_XOR_QUAD_CurrentVersionRun_eb97 {
  strings:
    $key_eb97 = { b8 f8 [2] 9c f6 [2] b7 da [2] 99 f8 [2] 8d e3 [2] 82 f9 [2] 9c e4 [2] 9e e5 [2] 85 e3 [2] 99 e4 [2] 85 cb }

  condition:
    any of them
}