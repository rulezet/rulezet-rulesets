rule TTP_XOR_QUAD_CurrentVersionRun_ee2f {
  strings:
    $key_ee2f = { bd 40 [2] 99 4e [2] b2 62 [2] 9c 40 [2] 88 5b [2] 87 41 [2] 99 5c [2] 9b 5d [2] 80 5b [2] 9c 5c [2] 80 73 }

  condition:
    any of them
}