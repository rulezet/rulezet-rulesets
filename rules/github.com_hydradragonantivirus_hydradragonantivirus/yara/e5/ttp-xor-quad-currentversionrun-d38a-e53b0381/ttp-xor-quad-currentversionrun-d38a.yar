rule TTP_XOR_QUAD_CurrentVersionRun_d38a {
  strings:
    $key_d38a = { 80 e5 [2] a4 eb [2] 8f c7 [2] a1 e5 [2] b5 fe [2] ba e4 [2] a4 f9 [2] a6 f8 [2] bd fe [2] a1 f9 [2] bd d6 }

  condition:
    any of them
}