rule TTP_XOR_QUAD_CurrentVersionRun_2ef6 {
  strings:
    $key_2ef6 = { 7d 99 [2] 59 97 [2] 72 bb [2] 5c 99 [2] 48 82 [2] 47 98 [2] 59 85 [2] 5b 84 [2] 40 82 [2] 5c 85 [2] 40 aa }

  condition:
    any of them
}