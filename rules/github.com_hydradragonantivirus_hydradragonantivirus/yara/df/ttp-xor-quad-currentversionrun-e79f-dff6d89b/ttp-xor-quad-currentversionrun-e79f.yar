rule TTP_XOR_QUAD_CurrentVersionRun_e79f {
  strings:
    $key_e79f = { b4 f0 [2] 90 fe [2] bb d2 [2] 95 f0 [2] 81 eb [2] 8e f1 [2] 90 ec [2] 92 ed [2] 89 eb [2] 95 ec [2] 89 c3 }

  condition:
    any of them
}