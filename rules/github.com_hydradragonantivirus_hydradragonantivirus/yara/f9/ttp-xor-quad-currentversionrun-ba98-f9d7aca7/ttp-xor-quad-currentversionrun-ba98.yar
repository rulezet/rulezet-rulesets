rule TTP_XOR_QUAD_CurrentVersionRun_ba98 {
  strings:
    $key_ba98 = { e9 f7 [2] cd f9 [2] e6 d5 [2] c8 f7 [2] dc ec [2] d3 f6 [2] cd eb [2] cf ea [2] d4 ec [2] c8 eb [2] d4 c4 }

  condition:
    any of them
}