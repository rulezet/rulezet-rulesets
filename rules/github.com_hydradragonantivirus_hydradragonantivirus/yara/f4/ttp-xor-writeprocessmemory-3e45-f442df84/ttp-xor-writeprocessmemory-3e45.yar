rule TTP_XOR_WriteProcessMemory_3e45 {
  strings:
    $key_3e45 = { 69 37 [2] 5b 15 [2] 5d 20 [2] 73 20 [2] 4c 3c }

  condition:
    any of them
}