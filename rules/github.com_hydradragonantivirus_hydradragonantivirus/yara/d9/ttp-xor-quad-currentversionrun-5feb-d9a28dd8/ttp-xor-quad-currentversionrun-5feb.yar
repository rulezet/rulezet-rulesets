rule TTP_XOR_QUAD_CurrentVersionRun_5feb {
  strings:
    $key_5feb = { 0c 84 [2] 28 8a [2] 03 a6 [2] 2d 84 [2] 39 9f [2] 36 85 [2] 28 98 [2] 2a 99 [2] 31 9f [2] 2d 98 [2] 31 b7 }

  condition:
    any of them
}