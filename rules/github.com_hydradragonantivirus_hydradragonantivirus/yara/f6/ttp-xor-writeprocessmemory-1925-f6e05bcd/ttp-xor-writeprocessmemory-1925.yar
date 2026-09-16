rule TTP_XOR_WriteProcessMemory_1925 {
  strings:
    $key_1925 = { 4e 57 [2] 7c 75 [2] 7a 40 [2] 54 40 [2] 6b 5c }

  condition:
    any of them
}