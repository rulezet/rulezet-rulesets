rule TTP_XOR_QUAD_CurrentVersionRun_16a6 {
  strings:
    $key_16a6 = { 45 c9 [2] 61 c7 [2] 4a eb [2] 64 c9 [2] 70 d2 [2] 7f c8 [2] 61 d5 [2] 63 d4 [2] 78 d2 [2] 64 d5 [2] 78 fa }

  condition:
    any of them
}