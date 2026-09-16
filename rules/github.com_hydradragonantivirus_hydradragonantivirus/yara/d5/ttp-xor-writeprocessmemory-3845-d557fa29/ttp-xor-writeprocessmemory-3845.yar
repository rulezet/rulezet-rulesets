rule TTP_XOR_WriteProcessMemory_3845 {
  strings:
    $key_3845 = { 6f 37 [2] 5d 15 [2] 5b 20 [2] 75 20 [2] 4a 3c }

  condition:
    any of them
}