rule TTP_XOR_QUAD_CurrentVersionRun_ee5d {
  strings:
    $key_ee5d = { bd 32 [2] 99 3c [2] b2 10 [2] 9c 32 [2] 88 29 [2] 87 33 [2] 99 2e [2] 9b 2f [2] 80 29 [2] 9c 2e [2] 80 01 }

  condition:
    any of them
}