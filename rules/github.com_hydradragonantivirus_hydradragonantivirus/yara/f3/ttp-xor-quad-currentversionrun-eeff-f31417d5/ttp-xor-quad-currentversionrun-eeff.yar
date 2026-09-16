rule TTP_XOR_QUAD_CurrentVersionRun_eeff {
  strings:
    $key_eeff = { bd 90 [2] 99 9e [2] b2 b2 [2] 9c 90 [2] 88 8b [2] 87 91 [2] 99 8c [2] 9b 8d [2] 80 8b [2] 9c 8c [2] 80 a3 }

  condition:
    any of them
}