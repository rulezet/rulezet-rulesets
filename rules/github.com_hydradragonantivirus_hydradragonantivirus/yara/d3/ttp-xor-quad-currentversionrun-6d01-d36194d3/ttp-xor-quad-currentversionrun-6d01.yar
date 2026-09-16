rule TTP_XOR_QUAD_CurrentVersionRun_6d01 {
  strings:
    $key_6d01 = { 3e 6e [2] 1a 60 [2] 31 4c [2] 1f 6e [2] 0b 75 [2] 04 6f [2] 1a 72 [2] 18 73 [2] 03 75 [2] 1f 72 [2] 03 5d }

  condition:
    any of them
}