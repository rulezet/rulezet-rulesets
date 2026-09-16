rule TTP_XOR_QUAD_CurrentVersionRun_3df6 {
  strings:
    $key_3df6 = { 6e 99 [2] 4a 97 [2] 61 bb [2] 4f 99 [2] 5b 82 [2] 54 98 [2] 4a 85 [2] 48 84 [2] 53 82 [2] 4f 85 [2] 53 aa }

  condition:
    any of them
}