rule TTP_XOR_QUAD_CurrentVersionRun_e282 {
  strings:
    $key_e282 = { b1 ed [2] 95 e3 [2] be cf [2] 90 ed [2] 84 f6 [2] 8b ec [2] 95 f1 [2] 97 f0 [2] 8c f6 [2] 90 f1 [2] 8c de }

  condition:
    any of them
}