rule TTP_XOR_QUAD_CurrentVersionRun_6d51 {
  strings:
    $key_6d51 = { 3e 3e [2] 1a 30 [2] 31 1c [2] 1f 3e [2] 0b 25 [2] 04 3f [2] 1a 22 [2] 18 23 [2] 03 25 [2] 1f 22 [2] 03 0d }

  condition:
    any of them
}