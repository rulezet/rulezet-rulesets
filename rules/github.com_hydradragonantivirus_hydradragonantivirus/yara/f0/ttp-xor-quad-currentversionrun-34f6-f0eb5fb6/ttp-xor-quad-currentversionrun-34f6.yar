rule TTP_XOR_QUAD_CurrentVersionRun_34f6 {
  strings:
    $key_34f6 = { 67 99 [2] 43 97 [2] 68 bb [2] 46 99 [2] 52 82 [2] 5d 98 [2] 43 85 [2] 41 84 [2] 5a 82 [2] 46 85 [2] 5a aa }

  condition:
    any of them
}