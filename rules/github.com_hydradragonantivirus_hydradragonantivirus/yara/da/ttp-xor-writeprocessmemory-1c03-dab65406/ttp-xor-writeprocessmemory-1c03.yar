rule TTP_XOR_WriteProcessMemory_1c03 {
  strings:
    $key_1c03 = { 4b 71 [2] 79 53 [2] 7f 66 [2] 51 66 [2] 6e 7a }

  condition:
    any of them
}