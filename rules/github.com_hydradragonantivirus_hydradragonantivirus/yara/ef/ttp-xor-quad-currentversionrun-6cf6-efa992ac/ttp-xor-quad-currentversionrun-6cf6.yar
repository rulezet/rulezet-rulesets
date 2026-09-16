rule TTP_XOR_QUAD_CurrentVersionRun_6cf6 {
  strings:
    $key_6cf6 = { 3f 99 [2] 1b 97 [2] 30 bb [2] 1e 99 [2] 0a 82 [2] 05 98 [2] 1b 85 [2] 19 84 [2] 02 82 [2] 1e 85 [2] 02 aa }

  condition:
    any of them
}