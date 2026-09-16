rule TTP_XOR_WriteProcessMemory_1027 {
  strings:
    $key_1027 = { 47 55 [2] 75 77 [2] 73 42 [2] 5d 42 [2] 62 5e }

  condition:
    any of them
}