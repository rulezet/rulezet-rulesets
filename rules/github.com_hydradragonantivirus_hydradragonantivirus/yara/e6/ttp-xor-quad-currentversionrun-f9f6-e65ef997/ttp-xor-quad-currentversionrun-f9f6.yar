rule TTP_XOR_QUAD_CurrentVersionRun_f9f6 {
  strings:
    $key_f9f6 = { aa 99 [2] 8e 97 [2] a5 bb [2] 8b 99 [2] 9f 82 [2] 90 98 [2] 8e 85 [2] 8c 84 [2] 97 82 [2] 8b 85 [2] 97 aa }

  condition:
    any of them
}