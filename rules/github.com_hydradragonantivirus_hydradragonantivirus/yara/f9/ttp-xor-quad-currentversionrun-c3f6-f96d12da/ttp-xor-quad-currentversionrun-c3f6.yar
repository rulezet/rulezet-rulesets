rule TTP_XOR_QUAD_CurrentVersionRun_c3f6 {
  strings:
    $key_c3f6 = { 90 99 [2] b4 97 [2] 9f bb [2] b1 99 [2] a5 82 [2] aa 98 [2] b4 85 [2] b6 84 [2] ad 82 [2] b1 85 [2] ad aa }

  condition:
    any of them
}