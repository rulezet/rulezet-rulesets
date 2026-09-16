rule TTP_XOR_QUAD_CurrentVersionRun_6351 {
  strings:
    $key_6351 = { 30 3e [2] 14 30 [2] 3f 1c [2] 11 3e [2] 05 25 [2] 0a 3f [2] 14 22 [2] 16 23 [2] 0d 25 [2] 11 22 [2] 0d 0d }

  condition:
    any of them
}