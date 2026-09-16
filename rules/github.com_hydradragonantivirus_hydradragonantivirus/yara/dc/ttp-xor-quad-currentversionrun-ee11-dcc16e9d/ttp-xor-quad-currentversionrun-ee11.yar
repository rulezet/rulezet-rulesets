rule TTP_XOR_QUAD_CurrentVersionRun_ee11 {
  strings:
    $key_ee11 = { bd 7e [2] 99 70 [2] b2 5c [2] 9c 7e [2] 88 65 [2] 87 7f [2] 99 62 [2] 9b 63 [2] 80 65 [2] 9c 62 [2] 80 4d }

  condition:
    any of them
}