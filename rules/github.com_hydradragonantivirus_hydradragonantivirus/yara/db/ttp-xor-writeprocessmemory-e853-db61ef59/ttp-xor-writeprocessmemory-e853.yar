rule TTP_XOR_WriteProcessMemory_e853 {
  strings:
    $key_e853 = { bf 21 [2] 8d 03 [2] 8b 36 [2] a5 36 [2] 9a 2a }

  condition:
    any of them
}