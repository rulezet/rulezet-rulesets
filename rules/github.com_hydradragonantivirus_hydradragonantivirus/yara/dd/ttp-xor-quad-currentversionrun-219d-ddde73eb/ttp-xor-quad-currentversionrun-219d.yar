rule TTP_XOR_QUAD_CurrentVersionRun_219d {
  strings:
    $key_219d = { 72 f2 [2] 56 fc [2] 7d d0 [2] 53 f2 [2] 47 e9 [2] 48 f3 [2] 56 ee [2] 54 ef [2] 4f e9 [2] 53 ee [2] 4f c1 }

  condition:
    any of them
}