rule TTP_XOR_QUAD_CurrentVersionRun_199f {
  strings:
    $key_199f = { 4a f0 [2] 6e fe [2] 45 d2 [2] 6b f0 [2] 7f eb [2] 70 f1 [2] 6e ec [2] 6c ed [2] 77 eb [2] 6b ec [2] 77 c3 }

  condition:
    any of them
}