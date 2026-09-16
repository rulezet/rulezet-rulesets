rule TTP_XOR_WriteProcessMemory_1b75 {
  strings:
    $key_1b75 = { 4c 07 [2] 7e 25 [2] 78 10 [2] 56 10 [2] 69 0c }

  condition:
    any of them
}