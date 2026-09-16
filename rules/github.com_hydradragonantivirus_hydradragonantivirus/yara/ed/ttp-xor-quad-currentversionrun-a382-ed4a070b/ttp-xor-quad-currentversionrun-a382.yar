rule TTP_XOR_QUAD_CurrentVersionRun_a382 {
  strings:
    $key_a382 = { f0 ed [2] d4 e3 [2] ff cf [2] d1 ed [2] c5 f6 [2] ca ec [2] d4 f1 [2] d6 f0 [2] cd f6 [2] d1 f1 [2] cd de }

  condition:
    any of them
}