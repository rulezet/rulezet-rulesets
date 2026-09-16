rule TTP_XOR_QUAD_CurrentVersionRun_ef8d {
  strings:
    $key_ef8d = { bc e2 [2] 98 ec [2] b3 c0 [2] 9d e2 [2] 89 f9 [2] 86 e3 [2] 98 fe [2] 9a ff [2] 81 f9 [2] 9d fe [2] 81 d1 }

  condition:
    any of them
}