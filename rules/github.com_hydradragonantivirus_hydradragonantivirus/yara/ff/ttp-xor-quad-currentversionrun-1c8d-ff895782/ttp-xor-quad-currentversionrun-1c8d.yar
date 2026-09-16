rule TTP_XOR_QUAD_CurrentVersionRun_1c8d {
  strings:
    $key_1c8d = { 4f e2 [2] 6b ec [2] 40 c0 [2] 6e e2 [2] 7a f9 [2] 75 e3 [2] 6b fe [2] 69 ff [2] 72 f9 [2] 6e fe [2] 72 d1 }

  condition:
    any of them
}