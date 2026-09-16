rule TTP_XOR_QUAD_CurrentVersionRun_ee0c {
  strings:
    $key_ee0c = { bd 63 [2] 99 6d [2] b2 41 [2] 9c 63 [2] 88 78 [2] 87 62 [2] 99 7f [2] 9b 7e [2] 80 78 [2] 9c 7f [2] 80 50 }

  condition:
    any of them
}