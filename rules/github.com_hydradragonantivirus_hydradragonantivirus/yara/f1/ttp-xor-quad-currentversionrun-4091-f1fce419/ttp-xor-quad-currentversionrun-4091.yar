rule TTP_XOR_QUAD_CurrentVersionRun_4091 {
  strings:
    $key_4091 = { 13 fe [2] 37 f0 [2] 1c dc [2] 32 fe [2] 26 e5 [2] 29 ff [2] 37 e2 [2] 35 e3 [2] 2e e5 [2] 32 e2 [2] 2e cd }

  condition:
    any of them
}