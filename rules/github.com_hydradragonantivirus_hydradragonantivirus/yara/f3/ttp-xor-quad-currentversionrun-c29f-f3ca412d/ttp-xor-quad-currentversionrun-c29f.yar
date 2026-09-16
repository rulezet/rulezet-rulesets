rule TTP_XOR_QUAD_CurrentVersionRun_c29f {
  strings:
    $key_c29f = { 91 f0 [2] b5 fe [2] 9e d2 [2] b0 f0 [2] a4 eb [2] ab f1 [2] b5 ec [2] b7 ed [2] ac eb [2] b0 ec [2] ac c3 }

  condition:
    any of them
}