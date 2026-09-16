rule TTP_XOR_QUAD_CurrentVersionRun_eef3 {
  strings:
    $key_eef3 = { bd 9c [2] 99 92 [2] b2 be [2] 9c 9c [2] 88 87 [2] 87 9d [2] 99 80 [2] 9b 81 [2] 80 87 [2] 9c 80 [2] 80 af }

  condition:
    any of them
}