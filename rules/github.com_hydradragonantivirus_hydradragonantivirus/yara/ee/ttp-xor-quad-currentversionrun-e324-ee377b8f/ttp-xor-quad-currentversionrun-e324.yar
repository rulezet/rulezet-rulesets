rule TTP_XOR_QUAD_CurrentVersionRun_e324 {
  strings:
    $key_e324 = { b0 4b [2] 94 45 [2] bf 69 [2] 91 4b [2] 85 50 [2] 8a 4a [2] 94 57 [2] 96 56 [2] 8d 50 [2] 91 57 [2] 8d 78 }

  condition:
    any of them
}