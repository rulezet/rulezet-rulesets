rule TTP_XOR_QUAD_CurrentVersionRun_019f {
  strings:
    $key_019f = { 52 f0 [2] 76 fe [2] 5d d2 [2] 73 f0 [2] 67 eb [2] 68 f1 [2] 76 ec [2] 74 ed [2] 6f eb [2] 73 ec [2] 6f c3 }

  condition:
    any of them
}