rule TTP_XOR_QUAD_CurrentVersionRun_7982 {
  strings:
    $key_7982 = { 2a ed [2] 0e e3 [2] 25 cf [2] 0b ed [2] 1f f6 [2] 10 ec [2] 0e f1 [2] 0c f0 [2] 17 f6 [2] 0b f1 [2] 17 de }

  condition:
    any of them
}