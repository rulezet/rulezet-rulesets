rule TTP_XOR_WriteProcessMemory_1c30 {
  strings:
    $key_1c30 = { 4b 42 [2] 79 60 [2] 7f 55 [2] 51 55 [2] 6e 49 }

  condition:
    any of them
}