rule TTP_XOR_QUAD_CurrentVersionRun_f1e0 {
  strings:
    $key_f1e0 = { a2 8f [2] 86 81 [2] ad ad [2] 83 8f [2] 97 94 [2] 98 8e [2] 86 93 [2] 84 92 [2] 9f 94 [2] 83 93 [2] 9f bc }

  condition:
    any of them
}