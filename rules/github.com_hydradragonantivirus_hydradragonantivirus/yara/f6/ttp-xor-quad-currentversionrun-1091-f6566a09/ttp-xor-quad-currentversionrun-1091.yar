rule TTP_XOR_QUAD_CurrentVersionRun_1091 {
  strings:
    $key_1091 = { 43 fe [2] 67 f0 [2] 4c dc [2] 62 fe [2] 76 e5 [2] 79 ff [2] 67 e2 [2] 65 e3 [2] 7e e5 [2] 62 e2 [2] 7e cd }

  condition:
    any of them
}