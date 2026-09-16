rule TTP_XOR_QUAD_CurrentVersionRun_0eab {
  strings:
    $key_0eab = { 5d c4 [2] 79 ca [2] 52 e6 [2] 7c c4 [2] 68 df [2] 67 c5 [2] 79 d8 [2] 7b d9 [2] 60 df [2] 7c d8 [2] 60 f7 }

  condition:
    any of them
}