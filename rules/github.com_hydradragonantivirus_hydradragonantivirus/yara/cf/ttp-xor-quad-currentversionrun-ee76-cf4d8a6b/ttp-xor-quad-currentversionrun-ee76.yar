rule TTP_XOR_QUAD_CurrentVersionRun_ee76 {
  strings:
    $key_ee76 = { bd 19 [2] 99 17 [2] b2 3b [2] 9c 19 [2] 88 02 [2] 87 18 [2] 99 05 [2] 9b 04 [2] 80 02 [2] 9c 05 [2] 80 2a }

  condition:
    any of them
}