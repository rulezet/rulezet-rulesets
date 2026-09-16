rule TTP_XOR_QUAD_CurrentVersionRun_ee65 {
  strings:
    $key_ee65 = { bd 0a [2] 99 04 [2] b2 28 [2] 9c 0a [2] 88 11 [2] 87 0b [2] 99 16 [2] 9b 17 [2] 80 11 [2] 9c 16 [2] 80 39 }

  condition:
    any of them
}