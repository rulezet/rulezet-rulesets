rule TTP_XOR_WriteProcessMemory_2e51 {
  strings:
    $key_2e51 = { 79 23 [2] 4b 01 [2] 4d 34 [2] 63 34 [2] 5c 28 }

  condition:
    any of them
}