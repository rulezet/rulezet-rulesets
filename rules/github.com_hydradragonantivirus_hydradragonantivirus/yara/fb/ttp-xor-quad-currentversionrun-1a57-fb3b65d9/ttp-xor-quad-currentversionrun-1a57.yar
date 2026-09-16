rule TTP_XOR_QUAD_CurrentVersionRun_1a57 {
  strings:
    $key_1a57 = { 49 38 [2] 6d 36 [2] 46 1a [2] 68 38 [2] 7c 23 [2] 73 39 [2] 6d 24 [2] 6f 25 [2] 74 23 [2] 68 24 [2] 74 0b }

  condition:
    any of them
}