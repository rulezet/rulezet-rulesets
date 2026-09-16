rule TTP_XOR_QUAD_CurrentVersionRun_f696 {
  strings:
    $key_f696 = { a5 f9 [2] 81 f7 [2] aa db [2] 84 f9 [2] 90 e2 [2] 9f f8 [2] 81 e5 [2] 83 e4 [2] 98 e2 [2] 84 e5 [2] 98 ca }

  condition:
    any of them
}