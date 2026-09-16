rule TTP_XOR_QUAD_CurrentVersionRun_f482 {
  strings:
    $key_f482 = { a7 ed [2] 83 e3 [2] a8 cf [2] 86 ed [2] 92 f6 [2] 9d ec [2] 83 f1 [2] 81 f0 [2] 9a f6 [2] 86 f1 [2] 9a de }

  condition:
    any of them
}