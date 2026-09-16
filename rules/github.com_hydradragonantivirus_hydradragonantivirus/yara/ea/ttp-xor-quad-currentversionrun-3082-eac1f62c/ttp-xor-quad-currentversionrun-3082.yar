rule TTP_XOR_QUAD_CurrentVersionRun_3082 {
  strings:
    $key_3082 = { 63 ed [2] 47 e3 [2] 6c cf [2] 42 ed [2] 56 f6 [2] 59 ec [2] 47 f1 [2] 45 f0 [2] 5e f6 [2] 42 f1 [2] 5e de }

  condition:
    any of them
}