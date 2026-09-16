rule TTP_XOR_QUAD_CurrentVersionRun_129f {
  strings:
    $key_129f = { 41 f0 [2] 65 fe [2] 4e d2 [2] 60 f0 [2] 74 eb [2] 7b f1 [2] 65 ec [2] 67 ed [2] 7c eb [2] 60 ec [2] 7c c3 }

  condition:
    any of them
}