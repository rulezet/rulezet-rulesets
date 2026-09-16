rule TTP_XOR_QUAD_CurrentVersionRun_7a9f {
  strings:
    $key_7a9f = { 29 f0 [2] 0d fe [2] 26 d2 [2] 08 f0 [2] 1c eb [2] 13 f1 [2] 0d ec [2] 0f ed [2] 14 eb [2] 08 ec [2] 14 c3 }

  condition:
    any of them
}