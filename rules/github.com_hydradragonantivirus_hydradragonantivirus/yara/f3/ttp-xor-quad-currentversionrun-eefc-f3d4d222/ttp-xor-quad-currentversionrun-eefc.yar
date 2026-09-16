rule TTP_XOR_QUAD_CurrentVersionRun_eefc {
  strings:
    $key_eefc = { bd 93 [2] 99 9d [2] b2 b1 [2] 9c 93 [2] 88 88 [2] 87 92 [2] 99 8f [2] 9b 8e [2] 80 88 [2] 9c 8f [2] 80 a0 }

  condition:
    any of them
}