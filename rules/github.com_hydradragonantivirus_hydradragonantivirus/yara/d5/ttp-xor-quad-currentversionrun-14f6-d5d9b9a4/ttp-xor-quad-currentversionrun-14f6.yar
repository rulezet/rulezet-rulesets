rule TTP_XOR_QUAD_CurrentVersionRun_14f6 {
  strings:
    $key_14f6 = { 47 99 [2] 63 97 [2] 48 bb [2] 66 99 [2] 72 82 [2] 7d 98 [2] 63 85 [2] 61 84 [2] 7a 82 [2] 66 85 [2] 7a aa }

  condition:
    any of them
}