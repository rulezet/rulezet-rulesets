rule TTP_XOR_QUAD_CurrentVersionRun_ebe0 {
  strings:
    $key_ebe0 = { b8 8f [2] 9c 81 [2] b7 ad [2] 99 8f [2] 8d 94 [2] 82 8e [2] 9c 93 [2] 9e 92 [2] 85 94 [2] 99 93 [2] 85 bc }

  condition:
    any of them
}