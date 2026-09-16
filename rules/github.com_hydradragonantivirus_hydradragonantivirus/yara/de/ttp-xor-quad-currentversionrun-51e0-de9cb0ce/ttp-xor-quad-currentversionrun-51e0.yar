rule TTP_XOR_QUAD_CurrentVersionRun_51e0 {
  strings:
    $key_51e0 = { 02 8f [2] 26 81 [2] 0d ad [2] 23 8f [2] 37 94 [2] 38 8e [2] 26 93 [2] 24 92 [2] 3f 94 [2] 23 93 [2] 3f bc }

  condition:
    any of them
}