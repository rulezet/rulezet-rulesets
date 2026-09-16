rule TTP_XOR_QUAD_CurrentVersionRun_d8d4 {
  strings:
    $key_d8d4 = { 8b bb [2] af b5 [2] 84 99 [2] aa bb [2] be a0 [2] b1 ba [2] af a7 [2] ad a6 [2] b6 a0 [2] aa a7 [2] b6 88 }

  condition:
    any of them
}