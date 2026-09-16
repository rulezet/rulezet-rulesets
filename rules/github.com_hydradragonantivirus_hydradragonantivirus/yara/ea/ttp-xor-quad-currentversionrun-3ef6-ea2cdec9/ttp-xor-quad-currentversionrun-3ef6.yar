rule TTP_XOR_QUAD_CurrentVersionRun_3ef6 {
  strings:
    $key_3ef6 = { 6d 99 [2] 49 97 [2] 62 bb [2] 4c 99 [2] 58 82 [2] 57 98 [2] 49 85 [2] 4b 84 [2] 50 82 [2] 4c 85 [2] 50 aa }

  condition:
    any of them
}