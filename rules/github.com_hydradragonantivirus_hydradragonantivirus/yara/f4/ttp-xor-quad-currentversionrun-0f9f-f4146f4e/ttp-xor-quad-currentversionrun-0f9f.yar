rule TTP_XOR_QUAD_CurrentVersionRun_0f9f {
  strings:
    $key_0f9f = { 5c f0 [2] 78 fe [2] 53 d2 [2] 7d f0 [2] 69 eb [2] 66 f1 [2] 78 ec [2] 7a ed [2] 61 eb [2] 7d ec [2] 61 c3 }

  condition:
    any of them
}