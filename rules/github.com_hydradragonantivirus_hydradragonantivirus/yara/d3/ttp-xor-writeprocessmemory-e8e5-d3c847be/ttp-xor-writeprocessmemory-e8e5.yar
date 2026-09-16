rule TTP_XOR_WriteProcessMemory_e8e5 {
  strings:
    $key_e8e5 = { bf 97 [2] 8d b5 [2] 8b 80 [2] a5 80 [2] 9a 9c }

  condition:
    any of them
}