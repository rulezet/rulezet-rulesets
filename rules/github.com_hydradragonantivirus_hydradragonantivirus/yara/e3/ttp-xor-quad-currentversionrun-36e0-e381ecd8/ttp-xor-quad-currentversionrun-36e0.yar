rule TTP_XOR_QUAD_CurrentVersionRun_36e0 {
  strings:
    $key_36e0 = { 65 8f [2] 41 81 [2] 6a ad [2] 44 8f [2] 50 94 [2] 5f 8e [2] 41 93 [2] 43 92 [2] 58 94 [2] 44 93 [2] 58 bc }

  condition:
    any of them
}