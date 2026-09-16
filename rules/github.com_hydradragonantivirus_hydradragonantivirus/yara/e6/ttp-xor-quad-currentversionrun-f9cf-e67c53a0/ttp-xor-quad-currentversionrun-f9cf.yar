rule TTP_XOR_QUAD_CurrentVersionRun_f9cf {
  strings:
    $key_f9cf = { aa a0 [2] 8e ae [2] a5 82 [2] 8b a0 [2] 9f bb [2] 90 a1 [2] 8e bc [2] 8c bd [2] 97 bb [2] 8b bc [2] 97 93 }

  condition:
    any of them
}