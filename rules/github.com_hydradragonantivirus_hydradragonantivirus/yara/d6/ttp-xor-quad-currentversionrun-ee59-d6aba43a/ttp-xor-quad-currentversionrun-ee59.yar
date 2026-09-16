rule TTP_XOR_QUAD_CurrentVersionRun_ee59 {
  strings:
    $key_ee59 = { bd 36 [2] 99 38 [2] b2 14 [2] 9c 36 [2] 88 2d [2] 87 37 [2] 99 2a [2] 9b 2b [2] 80 2d [2] 9c 2a [2] 80 05 }

  condition:
    any of them
}