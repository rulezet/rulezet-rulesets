rule TTP_XOR_WriteProcessMemory_1fe5 {
  strings:
    $key_1fe5 = { 48 97 [2] 7a b5 [2] 7c 80 [2] 52 80 [2] 6d 9c }

  condition:
    any of them
}