rule TTP_XOR_QUAD_CurrentVersionRun_f19d {
  strings:
    $key_f19d = { a2 f2 [2] 86 fc [2] ad d0 [2] 83 f2 [2] 97 e9 [2] 98 f3 [2] 86 ee [2] 84 ef [2] 9f e9 [2] 83 ee [2] 9f c1 }

  condition:
    any of them
}