rule TTP_XOR_QUAD_CurrentVersionRun_f8f6 {
  strings:
    $key_f8f6 = { ab 99 [2] 8f 97 [2] a4 bb [2] 8a 99 [2] 9e 82 [2] 91 98 [2] 8f 85 [2] 8d 84 [2] 96 82 [2] 8a 85 [2] 96 aa }

  condition:
    any of them
}