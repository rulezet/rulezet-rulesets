rule TTP_XOR_WriteProcessMemory_6e74 {
  strings:
    $key_6e74 = { 39 06 [2] 0b 24 [2] 0d 11 [2] 23 11 [2] 1c 0d }

  condition:
    any of them
}