rule TTP_XOR_QUAD_CurrentVersionRun_7782 {
  strings:
    $key_7782 = { 24 ed [2] 00 e3 [2] 2b cf [2] 05 ed [2] 11 f6 [2] 1e ec [2] 00 f1 [2] 02 f0 [2] 19 f6 [2] 05 f1 [2] 19 de }

  condition:
    any of them
}