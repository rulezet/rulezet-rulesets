rule TTP_XOR_QUAD_CurrentVersionRun_c1f6 {
  strings:
    $key_c1f6 = { 92 99 [2] b6 97 [2] 9d bb [2] b3 99 [2] a7 82 [2] a8 98 [2] b6 85 [2] b4 84 [2] af 82 [2] b3 85 [2] af aa }

  condition:
    any of them
}