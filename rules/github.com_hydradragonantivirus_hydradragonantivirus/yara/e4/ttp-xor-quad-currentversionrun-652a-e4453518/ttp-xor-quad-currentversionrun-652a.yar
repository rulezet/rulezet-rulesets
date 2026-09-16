rule TTP_XOR_QUAD_CurrentVersionRun_652a {
  strings:
    $key_652a = { 36 45 [2] 12 4b [2] 39 67 [2] 17 45 [2] 03 5e [2] 0c 44 [2] 12 59 [2] 10 58 [2] 0b 5e [2] 17 59 [2] 0b 76 }

  condition:
    any of them
}