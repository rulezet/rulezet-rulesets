rule TTP_XOR_QUAD_CurrentVersionRun_ddf6 {
  strings:
    $key_ddf6 = { 8e 99 [2] aa 97 [2] 81 bb [2] af 99 [2] bb 82 [2] b4 98 [2] aa 85 [2] a8 84 [2] b3 82 [2] af 85 [2] b3 aa }

  condition:
    any of them
}