rule TTP_XOR_QUAD_CurrentVersionRun_ee55 {
  strings:
    $key_ee55 = { bd 3a [2] 99 34 [2] b2 18 [2] 9c 3a [2] 88 21 [2] 87 3b [2] 99 26 [2] 9b 27 [2] 80 21 [2] 9c 26 [2] 80 09 }

  condition:
    any of them
}