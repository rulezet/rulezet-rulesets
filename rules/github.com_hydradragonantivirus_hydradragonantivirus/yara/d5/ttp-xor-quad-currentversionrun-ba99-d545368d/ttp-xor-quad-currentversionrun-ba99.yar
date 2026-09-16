rule TTP_XOR_QUAD_CurrentVersionRun_ba99 {
  strings:
    $key_ba99 = { e9 f6 [2] cd f8 [2] e6 d4 [2] c8 f6 [2] dc ed [2] d3 f7 [2] cd ea [2] cf eb [2] d4 ed [2] c8 ea [2] d4 c5 }

  condition:
    any of them
}