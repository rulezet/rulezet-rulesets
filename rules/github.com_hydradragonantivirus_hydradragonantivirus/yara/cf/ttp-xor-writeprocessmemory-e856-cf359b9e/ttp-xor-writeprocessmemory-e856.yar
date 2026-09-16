rule TTP_XOR_WriteProcessMemory_e856 {
  strings:
    $key_e856 = { bf 24 [2] 8d 06 [2] 8b 33 [2] a5 33 [2] 9a 2f }

  condition:
    any of them
}