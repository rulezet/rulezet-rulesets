rule TTP_XOR_QUAD_CurrentVersionRun_5a57 {
  strings:
    $key_5a57 = { 09 38 [2] 2d 36 [2] 06 1a [2] 28 38 [2] 3c 23 [2] 33 39 [2] 2d 24 [2] 2f 25 [2] 34 23 [2] 28 24 [2] 34 0b }

  condition:
    any of them
}