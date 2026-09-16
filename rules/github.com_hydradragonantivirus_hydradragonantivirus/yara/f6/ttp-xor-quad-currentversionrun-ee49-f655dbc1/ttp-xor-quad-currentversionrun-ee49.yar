rule TTP_XOR_QUAD_CurrentVersionRun_ee49 {
  strings:
    $key_ee49 = { bd 26 [2] 99 28 [2] b2 04 [2] 9c 26 [2] 88 3d [2] 87 27 [2] 99 3a [2] 9b 3b [2] 80 3d [2] 9c 3a [2] 80 15 }

  condition:
    any of them
}