rule TTP_XOR_QUAD_CurrentVersionRun_b64b {
  strings:
    $key_b64b = { e5 24 [2] c1 2a [2] ea 06 [2] c4 24 [2] d0 3f [2] df 25 [2] c1 38 [2] c3 39 [2] d8 3f [2] c4 38 [2] d8 17 }

  condition:
    any of them
}