rule TTP_XOR_QUAD_CurrentVersionRun_3182 {
  strings:
    $key_3182 = { 62 ed [2] 46 e3 [2] 6d cf [2] 43 ed [2] 57 f6 [2] 58 ec [2] 46 f1 [2] 44 f0 [2] 5f f6 [2] 43 f1 [2] 5f de }

  condition:
    any of them
}