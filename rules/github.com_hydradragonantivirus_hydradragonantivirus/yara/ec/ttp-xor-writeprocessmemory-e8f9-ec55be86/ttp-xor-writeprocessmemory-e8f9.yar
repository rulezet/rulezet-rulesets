rule TTP_XOR_WriteProcessMemory_e8f9 {
  strings:
    $key_e8f9 = { bf 8b [2] 8d a9 [2] 8b 9c [2] a5 9c [2] 9a 80 }

  condition:
    any of them
}