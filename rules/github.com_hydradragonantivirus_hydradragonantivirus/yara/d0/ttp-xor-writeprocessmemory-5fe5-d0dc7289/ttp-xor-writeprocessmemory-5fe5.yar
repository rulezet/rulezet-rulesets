rule TTP_XOR_WriteProcessMemory_5fe5 {
  strings:
    $key_5fe5 = { 08 97 [2] 3a b5 [2] 3c 80 [2] 12 80 [2] 2d 9c }

  condition:
    any of them
}