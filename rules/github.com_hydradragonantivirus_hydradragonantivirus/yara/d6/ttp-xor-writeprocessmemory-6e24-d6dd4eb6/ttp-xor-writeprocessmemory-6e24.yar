rule TTP_XOR_WriteProcessMemory_6e24 {
  strings:
    $key_6e24 = { 39 56 [2] 0b 74 [2] 0d 41 [2] 23 41 [2] 1c 5d }

  condition:
    any of them
}