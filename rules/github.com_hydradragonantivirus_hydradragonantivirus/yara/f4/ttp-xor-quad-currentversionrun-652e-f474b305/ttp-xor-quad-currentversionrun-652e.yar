rule TTP_XOR_QUAD_CurrentVersionRun_652e {
  strings:
    $key_652e = { 36 41 [2] 12 4f [2] 39 63 [2] 17 41 [2] 03 5a [2] 0c 40 [2] 12 5d [2] 10 5c [2] 0b 5a [2] 17 5d [2] 0b 72 }

  condition:
    any of them
}