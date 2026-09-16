rule TTP_XOR_QUAD_CurrentVersionRun_2a9f {
  strings:
    $key_2a9f = { 79 f0 [2] 5d fe [2] 76 d2 [2] 58 f0 [2] 4c eb [2] 43 f1 [2] 5d ec [2] 5f ed [2] 44 eb [2] 58 ec [2] 44 c3 }

  condition:
    any of them
}