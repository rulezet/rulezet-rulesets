rule TTP_XOR_QUAD_CurrentVersionRun_dc87 {
  strings:
    $key_dc87 = { 8f e8 [2] ab e6 [2] 80 ca [2] ae e8 [2] ba f3 [2] b5 e9 [2] ab f4 [2] a9 f5 [2] b2 f3 [2] ae f4 [2] b2 db }

  condition:
    any of them
}