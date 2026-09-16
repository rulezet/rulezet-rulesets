rule TTP_XOR_WriteProcessMemory_2345 {
  strings:
    $key_2345 = { 74 37 [2] 46 15 [2] 40 20 [2] 6e 20 [2] 51 3c }

  condition:
    any of them
}