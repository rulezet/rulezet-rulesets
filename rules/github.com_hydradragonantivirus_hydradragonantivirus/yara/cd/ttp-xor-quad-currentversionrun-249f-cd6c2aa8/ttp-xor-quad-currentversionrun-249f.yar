rule TTP_XOR_QUAD_CurrentVersionRun_249f {
  strings:
    $key_249f = { 77 f0 [2] 53 fe [2] 78 d2 [2] 56 f0 [2] 42 eb [2] 4d f1 [2] 53 ec [2] 51 ed [2] 4a eb [2] 56 ec [2] 4a c3 }

  condition:
    any of them
}