rule TTP_XOR_WriteProcessMemory_6435 {
  strings:
    $key_6435 = { 33 47 [2] 01 65 [2] 07 50 [2] 29 50 [2] 16 4c }

  condition:
    any of them
}