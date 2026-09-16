rule TTP_XOR_QUAD_CurrentVersionRun_7d8d {
  strings:
    $key_7d8d = { 2e e2 [2] 0a ec [2] 21 c0 [2] 0f e2 [2] 1b f9 [2] 14 e3 [2] 0a fe [2] 08 ff [2] 13 f9 [2] 0f fe [2] 13 d1 }

  condition:
    any of them
}