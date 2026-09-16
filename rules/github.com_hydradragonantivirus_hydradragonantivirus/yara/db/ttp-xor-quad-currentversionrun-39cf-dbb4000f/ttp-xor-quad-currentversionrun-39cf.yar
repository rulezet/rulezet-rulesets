rule TTP_XOR_QUAD_CurrentVersionRun_39cf {
  strings:
    $key_39cf = { 6a a0 [2] 4e ae [2] 65 82 [2] 4b a0 [2] 5f bb [2] 50 a1 [2] 4e bc [2] 4c bd [2] 57 bb [2] 4b bc [2] 57 93 }

  condition:
    any of them
}