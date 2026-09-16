rule TTP_XOR_QUAD_CurrentVersionRun_12c9 {
  strings:
    $key_12c9 = { 41 a6 [2] 65 a8 [2] 4e 84 [2] 60 a6 [2] 74 bd [2] 7b a7 [2] 65 ba [2] 67 bb [2] 7c bd [2] 60 ba [2] 7c 95 }

  condition:
    any of them
}