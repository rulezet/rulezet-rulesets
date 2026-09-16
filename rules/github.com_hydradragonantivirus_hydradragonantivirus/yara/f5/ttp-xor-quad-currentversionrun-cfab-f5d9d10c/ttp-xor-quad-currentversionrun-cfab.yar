rule TTP_XOR_QUAD_CurrentVersionRun_cfab {
  strings:
    $key_cfab = { 9c c4 [2] b8 ca [2] 93 e6 [2] bd c4 [2] a9 df [2] a6 c5 [2] b8 d8 [2] ba d9 [2] a1 df [2] bd d8 [2] a1 f7 }

  condition:
    any of them
}