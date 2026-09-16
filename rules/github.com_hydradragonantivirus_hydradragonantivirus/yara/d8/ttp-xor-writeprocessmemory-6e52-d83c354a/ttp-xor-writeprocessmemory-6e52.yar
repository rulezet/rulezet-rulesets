rule TTP_XOR_WriteProcessMemory_6e52 {
  strings:
    $key_6e52 = { 39 20 [2] 0b 02 [2] 0d 37 [2] 23 37 [2] 1c 2b }

  condition:
    any of them
}