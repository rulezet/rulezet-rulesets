rule TTP_XOR_WriteProcessMemory_6822 {
  strings:
    $key_6822 = { 3f 50 [2] 0d 72 [2] 0b 47 [2] 25 47 [2] 1a 5b }

  condition:
    any of them
}