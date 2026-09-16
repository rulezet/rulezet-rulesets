rule TTP_XOR_WriteProcessMemory_3855 {
  strings:
    $key_3855 = { 6f 27 [2] 5d 05 [2] 5b 30 [2] 75 30 [2] 4a 2c }

  condition:
    any of them
}