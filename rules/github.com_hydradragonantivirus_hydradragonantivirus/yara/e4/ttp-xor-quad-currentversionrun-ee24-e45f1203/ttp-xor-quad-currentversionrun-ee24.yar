rule TTP_XOR_QUAD_CurrentVersionRun_ee24 {
  strings:
    $key_ee24 = { bd 4b [2] 99 45 [2] b2 69 [2] 9c 4b [2] 88 50 [2] 87 4a [2] 99 57 [2] 9b 56 [2] 80 50 [2] 9c 57 [2] 80 78 }

  condition:
    any of them
}