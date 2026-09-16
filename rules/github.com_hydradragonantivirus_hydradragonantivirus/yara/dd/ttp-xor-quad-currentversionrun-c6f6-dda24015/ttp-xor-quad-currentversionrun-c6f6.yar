rule TTP_XOR_QUAD_CurrentVersionRun_c6f6 {
  strings:
    $key_c6f6 = { 95 99 [2] b1 97 [2] 9a bb [2] b4 99 [2] a0 82 [2] af 98 [2] b1 85 [2] b3 84 [2] a8 82 [2] b4 85 [2] a8 aa }

  condition:
    any of them
}