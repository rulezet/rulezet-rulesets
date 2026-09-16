rule TTP_XOR_WriteProcessMemory_6415 {
  strings:
    $key_6415 = { 33 67 [2] 01 45 [2] 07 70 [2] 29 70 [2] 16 6c }

  condition:
    any of them
}