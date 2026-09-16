rule TTP_XOR_QUAD_CurrentVersionRun_32c9 {
  strings:
    $key_32c9 = { 61 a6 [2] 45 a8 [2] 6e 84 [2] 40 a6 [2] 54 bd [2] 5b a7 [2] 45 ba [2] 47 bb [2] 5c bd [2] 40 ba [2] 5c 95 }

  condition:
    any of them
}