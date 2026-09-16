rule TTP_XOR_QUAD_CurrentVersionRun_ee3c {
  strings:
    $key_ee3c = { bd 53 [2] 99 5d [2] b2 71 [2] 9c 53 [2] 88 48 [2] 87 52 [2] 99 4f [2] 9b 4e [2] 80 48 [2] 9c 4f [2] 80 60 }

  condition:
    any of them
}