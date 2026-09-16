rule TTP_XOR_WriteProcessMemory_5368 {
  strings:
    $key_5368 = { 04 1a [2] 36 38 [2] 30 0d [2] 1e 0d [2] 21 11 }

  condition:
    any of them
}