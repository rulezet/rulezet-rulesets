rule TTP_XOR_WriteProcessMemory_1c60 {
  strings:
    $key_1c60 = { 4b 12 [2] 79 30 [2] 7f 05 [2] 51 05 [2] 6e 19 }

  condition:
    any of them
}