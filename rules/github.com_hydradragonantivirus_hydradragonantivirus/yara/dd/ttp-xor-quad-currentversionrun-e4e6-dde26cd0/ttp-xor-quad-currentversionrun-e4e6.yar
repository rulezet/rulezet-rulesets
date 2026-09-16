rule TTP_XOR_QUAD_CurrentVersionRun_e4e6 {
  strings:
    $key_e4e6 = { b7 89 [2] 93 87 [2] b8 ab [2] 96 89 [2] 82 92 [2] 8d 88 [2] 93 95 [2] 91 94 [2] 8a 92 [2] 96 95 [2] 8a ba }

  condition:
    any of them
}