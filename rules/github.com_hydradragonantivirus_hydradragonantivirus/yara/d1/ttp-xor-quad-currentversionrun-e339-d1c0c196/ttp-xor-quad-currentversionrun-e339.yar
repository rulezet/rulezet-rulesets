rule TTP_XOR_QUAD_CurrentVersionRun_e339 {
  strings:
    $key_e339 = { b0 56 [2] 94 58 [2] bf 74 [2] 91 56 [2] 85 4d [2] 8a 57 [2] 94 4a [2] 96 4b [2] 8d 4d [2] 91 4a [2] 8d 65 }

  condition:
    any of them
}