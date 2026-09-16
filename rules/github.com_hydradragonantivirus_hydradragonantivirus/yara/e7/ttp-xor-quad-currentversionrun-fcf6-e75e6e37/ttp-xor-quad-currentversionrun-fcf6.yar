rule TTP_XOR_QUAD_CurrentVersionRun_fcf6 {
  strings:
    $key_fcf6 = { af 99 [2] 8b 97 [2] a0 bb [2] 8e 99 [2] 9a 82 [2] 95 98 [2] 8b 85 [2] 89 84 [2] 92 82 [2] 8e 85 [2] 92 aa }

  condition:
    any of them
}