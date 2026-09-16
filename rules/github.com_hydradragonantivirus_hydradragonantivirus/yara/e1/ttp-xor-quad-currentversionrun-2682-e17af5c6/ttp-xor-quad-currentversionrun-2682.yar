rule TTP_XOR_QUAD_CurrentVersionRun_2682 {
  strings:
    $key_2682 = { 75 ed [2] 51 e3 [2] 7a cf [2] 54 ed [2] 40 f6 [2] 4f ec [2] 51 f1 [2] 53 f0 [2] 48 f6 [2] 54 f1 [2] 48 de }

  condition:
    any of them
}