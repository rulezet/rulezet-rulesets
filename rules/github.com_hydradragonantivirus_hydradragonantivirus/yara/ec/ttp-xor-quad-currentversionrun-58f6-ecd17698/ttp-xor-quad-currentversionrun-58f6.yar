rule TTP_XOR_QUAD_CurrentVersionRun_58f6 {
  strings:
    $key_58f6 = { 0b 99 [2] 2f 97 [2] 04 bb [2] 2a 99 [2] 3e 82 [2] 31 98 [2] 2f 85 [2] 2d 84 [2] 36 82 [2] 2a 85 [2] 36 aa }

  condition:
    any of them
}