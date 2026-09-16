rule TTP_XOR_WriteProcessMemory_6245 {
  strings:
    $key_6245 = { 35 37 [2] 07 15 [2] 01 20 [2] 2f 20 [2] 10 3c }

  condition:
    any of them
}