rule TTP_XOR_QUAD_CurrentVersionRun_ee4c {
  strings:
    $key_ee4c = { bd 23 [2] 99 2d [2] b2 01 [2] 9c 23 [2] 88 38 [2] 87 22 [2] 99 3f [2] 9b 3e [2] 80 38 [2] 9c 3f [2] 80 10 }

  condition:
    any of them
}