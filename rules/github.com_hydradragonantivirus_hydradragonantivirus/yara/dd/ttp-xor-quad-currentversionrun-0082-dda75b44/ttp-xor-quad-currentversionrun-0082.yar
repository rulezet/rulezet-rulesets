rule TTP_XOR_QUAD_CurrentVersionRun_0082 {
  strings:
    $key_0082 = { 53 ed [2] 77 e3 [2] 5c cf [2] 72 ed [2] 66 f6 [2] 69 ec [2] 77 f1 [2] 75 f0 [2] 6e f6 [2] 72 f1 [2] 6e de }

  condition:
    any of them
}