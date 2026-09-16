rule TTP_XOR_WriteProcessMemory_2e13 {
  strings:
    $key_2e13 = { 79 61 [2] 4b 43 [2] 4d 76 [2] 63 76 [2] 5c 6a }

  condition:
    any of them
}