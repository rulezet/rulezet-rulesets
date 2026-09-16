rule TTP_XOR_WriteProcessMemory_2e60 {
  strings:
    $key_2e60 = { 79 12 [2] 4b 30 [2] 4d 05 [2] 63 05 [2] 5c 19 }

  condition:
    any of them
}