rule TTP_XOR_QUAD_CurrentVersionRun_e3c4 {
  strings:
    $key_e3c4 = { b0 ab [2] 94 a5 [2] bf 89 [2] 91 ab [2] 85 b0 [2] 8a aa [2] 94 b7 [2] 96 b6 [2] 8d b0 [2] 91 b7 [2] 8d 98 }

  condition:
    any of them
}