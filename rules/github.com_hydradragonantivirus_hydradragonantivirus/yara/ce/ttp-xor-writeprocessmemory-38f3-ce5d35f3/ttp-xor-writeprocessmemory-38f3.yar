rule TTP_XOR_WriteProcessMemory_38f3 {
  strings:
    $key_38f3 = { 6f 81 [2] 5d a3 [2] 5b 96 [2] 75 96 [2] 4a 8a }

  condition:
    any of them
}