rule TTP_XOR_QUAD_CurrentVersionRun_6082 {
  strings:
    $key_6082 = { 33 ed [2] 17 e3 [2] 3c cf [2] 12 ed [2] 06 f6 [2] 09 ec [2] 17 f1 [2] 15 f0 [2] 0e f6 [2] 12 f1 [2] 0e de }

  condition:
    any of them
}