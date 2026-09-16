rule TTP_XOR_QUAD_CurrentVersionRun_def6 {
  strings:
    $key_def6 = { 8d 99 [2] a9 97 [2] 82 bb [2] ac 99 [2] b8 82 [2] b7 98 [2] a9 85 [2] ab 84 [2] b0 82 [2] ac 85 [2] b0 aa }

  condition:
    any of them
}