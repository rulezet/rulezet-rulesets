rule TTP_XOR_QUAD_CurrentVersionRun_ee23 {
  strings:
    $key_ee23 = { bd 4c [2] 99 42 [2] b2 6e [2] 9c 4c [2] 88 57 [2] 87 4d [2] 99 50 [2] 9b 51 [2] 80 57 [2] 9c 50 [2] 80 7f }

  condition:
    any of them
}