rule TTP_XOR_QUAD_CurrentVersionRun_ee46 {
  strings:
    $key_ee46 = { bd 29 [2] 99 27 [2] b2 0b [2] 9c 29 [2] 88 32 [2] 87 28 [2] 99 35 [2] 9b 34 [2] 80 32 [2] 9c 35 [2] 80 1a }

  condition:
    any of them
}