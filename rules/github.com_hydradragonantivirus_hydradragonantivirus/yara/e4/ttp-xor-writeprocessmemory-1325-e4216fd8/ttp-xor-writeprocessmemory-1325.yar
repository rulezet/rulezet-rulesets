rule TTP_XOR_WriteProcessMemory_1325 {
  strings:
    $key_1325 = { 44 57 [2] 76 75 [2] 70 40 [2] 5e 40 [2] 61 5c }

  condition:
    any of them
}