rule TTP_XOR_QUAD_CurrentVersionRun_1ae0 {
  strings:
    $key_1ae0 = { 49 8f [2] 6d 81 [2] 46 ad [2] 68 8f [2] 7c 94 [2] 73 8e [2] 6d 93 [2] 6f 92 [2] 74 94 [2] 68 93 [2] 74 bc }

  condition:
    any of them
}