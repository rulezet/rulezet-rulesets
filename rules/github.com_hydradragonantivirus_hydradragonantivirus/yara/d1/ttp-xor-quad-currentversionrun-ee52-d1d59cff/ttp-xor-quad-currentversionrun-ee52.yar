rule TTP_XOR_QUAD_CurrentVersionRun_ee52 {
  strings:
    $key_ee52 = { bd 3d [2] 99 33 [2] b2 1f [2] 9c 3d [2] 88 26 [2] 87 3c [2] 99 21 [2] 9b 20 [2] 80 26 [2] 9c 21 [2] 80 0e }

  condition:
    any of them
}