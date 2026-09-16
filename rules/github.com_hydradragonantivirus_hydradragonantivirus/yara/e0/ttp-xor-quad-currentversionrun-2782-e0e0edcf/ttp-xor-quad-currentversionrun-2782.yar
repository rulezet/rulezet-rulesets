rule TTP_XOR_QUAD_CurrentVersionRun_2782 {
  strings:
    $key_2782 = { 74 ed [2] 50 e3 [2] 7b cf [2] 55 ed [2] 41 f6 [2] 4e ec [2] 50 f1 [2] 52 f0 [2] 49 f6 [2] 55 f1 [2] 49 de }

  condition:
    any of them
}