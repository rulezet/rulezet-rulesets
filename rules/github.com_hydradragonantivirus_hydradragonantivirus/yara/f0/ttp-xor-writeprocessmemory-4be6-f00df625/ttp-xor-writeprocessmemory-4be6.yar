rule TTP_XOR_WriteProcessMemory_4be6 {
  strings:
    $key_4be6 = { 1c 94 [2] 2e b6 [2] 28 83 [2] 06 83 [2] 39 9f }

  condition:
    any of them
}