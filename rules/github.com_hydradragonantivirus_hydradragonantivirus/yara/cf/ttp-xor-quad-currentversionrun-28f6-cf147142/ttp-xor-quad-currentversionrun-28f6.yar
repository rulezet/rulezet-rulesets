rule TTP_XOR_QUAD_CurrentVersionRun_28f6 {
  strings:
    $key_28f6 = { 7b 99 [2] 5f 97 [2] 74 bb [2] 5a 99 [2] 4e 82 [2] 41 98 [2] 5f 85 [2] 5d 84 [2] 46 82 [2] 5a 85 [2] 46 aa }

  condition:
    any of them
}