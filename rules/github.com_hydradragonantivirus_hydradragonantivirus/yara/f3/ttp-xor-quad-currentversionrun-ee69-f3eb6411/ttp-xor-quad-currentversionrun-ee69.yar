rule TTP_XOR_QUAD_CurrentVersionRun_ee69 {
  strings:
    $key_ee69 = { bd 06 [2] 99 08 [2] b2 24 [2] 9c 06 [2] 88 1d [2] 87 07 [2] 99 1a [2] 9b 1b [2] 80 1d [2] 9c 1a [2] 80 35 }

  condition:
    any of them
}