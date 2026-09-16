rule TTP_XOR_QUAD_CurrentVersionRun_b17b {
  strings:
    $key_b17b = { e2 14 [2] c6 1a [2] ed 36 [2] c3 14 [2] d7 0f [2] d8 15 [2] c6 08 [2] c4 09 [2] df 0f [2] c3 08 [2] df 27 }

  condition:
    any of them
}