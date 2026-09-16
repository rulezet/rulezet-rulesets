rule TTP_XOR_QUAD_CurrentVersionRun_7cf6 {
  strings:
    $key_7cf6 = { 2f 99 [2] 0b 97 [2] 20 bb [2] 0e 99 [2] 1a 82 [2] 15 98 [2] 0b 85 [2] 09 84 [2] 12 82 [2] 0e 85 [2] 12 aa }

  condition:
    any of them
}