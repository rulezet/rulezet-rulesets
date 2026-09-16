rule TTP_XOR_QUAD_CurrentVersionRun_7c51 {
  strings:
    $key_7c51 = { 2f 3e [2] 0b 30 [2] 20 1c [2] 0e 3e [2] 1a 25 [2] 15 3f [2] 0b 22 [2] 09 23 [2] 12 25 [2] 0e 22 [2] 12 0d }

  condition:
    any of them
}