rule TTP_XOR_WriteProcessMemory_1ef3 {
  strings:
    $key_1ef3 = { 49 81 [2] 7b a3 [2] 7d 96 [2] 53 96 [2] 6c 8a }

  condition:
    any of them
}