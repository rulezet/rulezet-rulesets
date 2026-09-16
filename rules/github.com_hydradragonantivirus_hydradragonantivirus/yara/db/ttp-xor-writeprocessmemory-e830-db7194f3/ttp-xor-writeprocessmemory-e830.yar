rule TTP_XOR_WriteProcessMemory_e830 {
  strings:
    $key_e830 = { bf 42 [2] 8d 60 [2] 8b 55 [2] a5 55 [2] 9a 49 }

  condition:
    any of them
}