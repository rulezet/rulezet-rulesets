rule TTP_XOR_QUAD_CurrentVersionRun_c09f {
  strings:
    $key_c09f = { 93 f0 [2] b7 fe [2] 9c d2 [2] b2 f0 [2] a6 eb [2] a9 f1 [2] b7 ec [2] b5 ed [2] ae eb [2] b2 ec [2] ae c3 }

  condition:
    any of them
}