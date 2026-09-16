rule TTP_XOR_WriteProcessMemory_e876 {
  strings:
    $key_e876 = { bf 04 [2] 8d 26 [2] 8b 13 [2] a5 13 [2] 9a 0f }

  condition:
    any of them
}