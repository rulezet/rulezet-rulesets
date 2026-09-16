rule TTP_XOR_WriteProcessMemory_11e5 {
  strings:
    $key_11e5 = { 46 97 [2] 74 b5 [2] 72 80 [2] 5c 80 [2] 63 9c }

  condition:
    any of them
}