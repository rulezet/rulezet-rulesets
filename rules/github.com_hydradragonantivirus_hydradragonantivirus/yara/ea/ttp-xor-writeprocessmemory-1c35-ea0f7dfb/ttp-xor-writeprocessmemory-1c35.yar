rule TTP_XOR_WriteProcessMemory_1c35 {
  strings:
    $key_1c35 = { 4b 47 [2] 79 65 [2] 7f 50 [2] 51 50 [2] 6e 4c }

  condition:
    any of them
}