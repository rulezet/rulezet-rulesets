rule TTP_XOR_QUAD_CurrentVersionRun_699f {
  strings:
    $key_699f = { 3a f0 [2] 1e fe [2] 35 d2 [2] 1b f0 [2] 0f eb [2] 00 f1 [2] 1e ec [2] 1c ed [2] 07 eb [2] 1b ec [2] 07 c3 }

  condition:
    any of them
}