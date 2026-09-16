rule TTP_XOR_QUAD_CurrentVersionRun_3087 {
  strings:
    $key_3087 = { 63 e8 [2] 47 e6 [2] 6c ca [2] 42 e8 [2] 56 f3 [2] 59 e9 [2] 47 f4 [2] 45 f5 [2] 5e f3 [2] 42 f4 [2] 5e db }

  condition:
    any of them
}