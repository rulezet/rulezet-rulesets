rule TTP_XOR_QUAD_CurrentVersionRun_ee60 {
  strings:
    $key_ee60 = { bd 0f [2] 99 01 [2] b2 2d [2] 9c 0f [2] 88 14 [2] 87 0e [2] 99 13 [2] 9b 12 [2] 80 14 [2] 9c 13 [2] 80 3c }

  condition:
    any of them
}