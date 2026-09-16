rule TTP_XOR_QUAD_CurrentVersionRun_09f6 {
  strings:
    $key_09f6 = { 5a 99 [2] 7e 97 [2] 55 bb [2] 7b 99 [2] 6f 82 [2] 60 98 [2] 7e 85 [2] 7c 84 [2] 67 82 [2] 7b 85 [2] 67 aa }

  condition:
    any of them
}