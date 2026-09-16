rule TTP_XOR_WriteProcessMemory_e841 {
  strings:
    $key_e841 = { bf 33 [2] 8d 11 [2] 8b 24 [2] a5 24 [2] 9a 38 }

  condition:
    any of them
}