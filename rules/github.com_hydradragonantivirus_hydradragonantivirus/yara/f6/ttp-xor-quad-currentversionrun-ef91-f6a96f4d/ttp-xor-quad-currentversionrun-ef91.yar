rule TTP_XOR_QUAD_CurrentVersionRun_ef91 {
  strings:
    $key_ef91 = { bc fe [2] 98 f0 [2] b3 dc [2] 9d fe [2] 89 e5 [2] 86 ff [2] 98 e2 [2] 9a e3 [2] 81 e5 [2] 9d e2 [2] 81 cd }

  condition:
    any of them
}