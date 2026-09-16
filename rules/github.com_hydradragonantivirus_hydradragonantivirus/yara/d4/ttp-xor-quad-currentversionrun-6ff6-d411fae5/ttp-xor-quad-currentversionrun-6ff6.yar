rule TTP_XOR_QUAD_CurrentVersionRun_6ff6 {
  strings:
    $key_6ff6 = { 3c 99 [2] 18 97 [2] 33 bb [2] 1d 99 [2] 09 82 [2] 06 98 [2] 18 85 [2] 1a 84 [2] 01 82 [2] 1d 85 [2] 01 aa }

  condition:
    any of them
}