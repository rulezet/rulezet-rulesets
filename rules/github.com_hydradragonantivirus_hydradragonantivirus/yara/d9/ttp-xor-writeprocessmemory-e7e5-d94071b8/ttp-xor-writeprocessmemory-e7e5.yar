rule TTP_XOR_WriteProcessMemory_e7e5 {
  strings:
    $key_e7e5 = { b0 97 [2] 82 b5 [2] 84 80 [2] aa 80 [2] 95 9c }

  condition:
    any of them
}