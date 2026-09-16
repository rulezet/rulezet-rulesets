rule TTP_XOR_QUAD_CurrentVersionRun_ff8d {
  strings:
    $key_ff8d = { ac e2 [2] 88 ec [2] a3 c0 [2] 8d e2 [2] 99 f9 [2] 96 e3 [2] 88 fe [2] 8a ff [2] 91 f9 [2] 8d fe [2] 91 d1 }

  condition:
    any of them
}