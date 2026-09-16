rule TTP_XOR_QUAD_CurrentVersionRun_f082 {
  strings:
    $key_f082 = { a3 ed [2] 87 e3 [2] ac cf [2] 82 ed [2] 96 f6 [2] 99 ec [2] 87 f1 [2] 85 f0 [2] 9e f6 [2] 82 f1 [2] 9e de }

  condition:
    any of them
}