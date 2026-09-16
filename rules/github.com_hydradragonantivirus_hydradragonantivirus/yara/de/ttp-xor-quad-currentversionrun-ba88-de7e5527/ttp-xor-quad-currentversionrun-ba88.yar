rule TTP_XOR_QUAD_CurrentVersionRun_ba88 {
  strings:
    $key_ba88 = { e9 e7 [2] cd e9 [2] e6 c5 [2] c8 e7 [2] dc fc [2] d3 e6 [2] cd fb [2] cf fa [2] d4 fc [2] c8 fb [2] d4 d4 }

  condition:
    any of them
}