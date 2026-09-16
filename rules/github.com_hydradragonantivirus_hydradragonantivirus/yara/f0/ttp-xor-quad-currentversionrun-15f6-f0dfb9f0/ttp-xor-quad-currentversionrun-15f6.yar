rule TTP_XOR_QUAD_CurrentVersionRun_15f6 {
  strings:
    $key_15f6 = { 46 99 [2] 62 97 [2] 49 bb [2] 67 99 [2] 73 82 [2] 7c 98 [2] 62 85 [2] 60 84 [2] 7b 82 [2] 67 85 [2] 7b aa }

  condition:
    any of them
}