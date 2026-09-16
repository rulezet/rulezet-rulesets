rule TTP_XOR_WriteProcessMemory_1be7 {
  strings:
    $key_1be7 = { 4c 95 [2] 7e b7 [2] 78 82 [2] 56 82 [2] 69 9e }

  condition:
    any of them
}