rule TTP_XOR_WriteProcessMemory_6e51 {
  strings:
    $key_6e51 = { 39 23 [2] 0b 01 [2] 0d 34 [2] 23 34 [2] 1c 28 }

  condition:
    any of them
}