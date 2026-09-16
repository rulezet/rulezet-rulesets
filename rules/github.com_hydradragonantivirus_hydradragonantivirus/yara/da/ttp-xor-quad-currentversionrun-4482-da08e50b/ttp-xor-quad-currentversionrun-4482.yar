rule TTP_XOR_QUAD_CurrentVersionRun_4482 {
  strings:
    $key_4482 = { 17 ed [2] 33 e3 [2] 18 cf [2] 36 ed [2] 22 f6 [2] 2d ec [2] 33 f1 [2] 31 f0 [2] 2a f6 [2] 36 f1 [2] 2a de }

  condition:
    any of them
}