rule TTP_XOR_WriteProcessMemory_6e67 {
  strings:
    $key_6e67 = { 39 15 [2] 0b 37 [2] 0d 02 [2] 23 02 [2] 1c 1e }

  condition:
    any of them
}