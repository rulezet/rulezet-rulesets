rule TTP_XOR_WriteProcessMemory_2e40 {
  strings:
    $key_2e40 = { 79 32 [2] 4b 10 [2] 4d 25 [2] 63 25 [2] 5c 39 }

  condition:
    any of them
}