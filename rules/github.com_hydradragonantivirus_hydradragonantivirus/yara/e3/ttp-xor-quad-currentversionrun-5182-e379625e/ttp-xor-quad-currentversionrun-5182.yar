rule TTP_XOR_QUAD_CurrentVersionRun_5182 {
  strings:
    $key_5182 = { 02 ed [2] 26 e3 [2] 0d cf [2] 23 ed [2] 37 f6 [2] 38 ec [2] 26 f1 [2] 24 f0 [2] 3f f6 [2] 23 f1 [2] 3f de }

  condition:
    any of them
}