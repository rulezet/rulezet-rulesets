rule TTP_XOR_WriteProcessMemory_1c25 {
  strings:
    $key_1c25 = { 4b 57 [2] 79 75 [2] 7f 40 [2] 51 40 [2] 6e 5c }

  condition:
    any of them
}