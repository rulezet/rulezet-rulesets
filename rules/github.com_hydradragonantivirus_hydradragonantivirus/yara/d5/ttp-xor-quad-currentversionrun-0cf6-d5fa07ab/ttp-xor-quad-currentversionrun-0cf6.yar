rule TTP_XOR_QUAD_CurrentVersionRun_0cf6 {
  strings:
    $key_0cf6 = { 5f 99 [2] 7b 97 [2] 50 bb [2] 7e 99 [2] 6a 82 [2] 65 98 [2] 7b 85 [2] 79 84 [2] 62 82 [2] 7e 85 [2] 62 aa }

  condition:
    any of them
}