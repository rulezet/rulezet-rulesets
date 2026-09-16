rule TTP_XOR_QUAD_CurrentVersionRun_ee7f {
  strings:
    $key_ee7f = { bd 10 [2] 99 1e [2] b2 32 [2] 9c 10 [2] 88 0b [2] 87 11 [2] 99 0c [2] 9b 0d [2] 80 0b [2] 9c 0c [2] 80 23 }

  condition:
    any of them
}