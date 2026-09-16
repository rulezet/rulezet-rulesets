rule TTP_XOR_QUAD_CurrentVersionRun_ee1c {
  strings:
    $key_ee1c = { bd 73 [2] 99 7d [2] b2 51 [2] 9c 73 [2] 88 68 [2] 87 72 [2] 99 6f [2] 9b 6e [2] 80 68 [2] 9c 6f [2] 80 40 }

  condition:
    any of them
}