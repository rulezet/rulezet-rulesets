rule TTP_XOR_QUAD_CurrentVersionRun_08e0 {
  strings:
    $key_08e0 = { 5b 8f [2] 7f 81 [2] 54 ad [2] 7a 8f [2] 6e 94 [2] 61 8e [2] 7f 93 [2] 7d 92 [2] 66 94 [2] 7a 93 [2] 66 bc }

  condition:
    any of them
}