rule TTP_XOR_WriteProcessMemory_537c {
  strings:
    $key_537c = { 04 0e [2] 36 2c [2] 30 19 [2] 1e 19 [2] 21 05 }

  condition:
    any of them
}