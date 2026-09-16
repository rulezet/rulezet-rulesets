rule TTP_XOR_WriteProcessMemory_4e45 {
  strings:
    $key_4e45 = { 19 37 [2] 2b 15 [2] 2d 20 [2] 03 20 [2] 3c 3c }

  condition:
    any of them
}