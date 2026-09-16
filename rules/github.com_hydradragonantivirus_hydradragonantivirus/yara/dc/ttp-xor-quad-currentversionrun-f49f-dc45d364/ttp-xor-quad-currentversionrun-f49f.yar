rule TTP_XOR_QUAD_CurrentVersionRun_f49f {
  strings:
    $key_f49f = { a7 f0 [2] 83 fe [2] a8 d2 [2] 86 f0 [2] 92 eb [2] 9d f1 [2] 83 ec [2] 81 ed [2] 9a eb [2] 86 ec [2] 9a c3 }

  condition:
    any of them
}