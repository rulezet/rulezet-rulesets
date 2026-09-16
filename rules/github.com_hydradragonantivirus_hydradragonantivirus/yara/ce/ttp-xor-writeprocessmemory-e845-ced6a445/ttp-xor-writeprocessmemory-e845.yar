rule TTP_XOR_WriteProcessMemory_e845 {
  strings:
    $key_e845 = { bf 37 [2] 8d 15 [2] 8b 20 [2] a5 20 [2] 9a 3c }

  condition:
    any of them
}