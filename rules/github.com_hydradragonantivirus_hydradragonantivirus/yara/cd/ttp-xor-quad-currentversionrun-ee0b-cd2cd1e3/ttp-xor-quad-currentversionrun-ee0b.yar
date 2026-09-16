rule TTP_XOR_QUAD_CurrentVersionRun_ee0b {
  strings:
    $key_ee0b = { bd 64 [2] 99 6a [2] b2 46 [2] 9c 64 [2] 88 7f [2] 87 65 [2] 99 78 [2] 9b 79 [2] 80 7f [2] 9c 78 [2] 80 57 }

  condition:
    any of them
}