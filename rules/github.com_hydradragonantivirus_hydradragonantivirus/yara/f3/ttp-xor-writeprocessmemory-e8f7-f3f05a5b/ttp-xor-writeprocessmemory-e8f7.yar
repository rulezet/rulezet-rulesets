rule TTP_XOR_WriteProcessMemory_e8f7 {
  strings:
    $key_e8f7 = { bf 85 [2] 8d a7 [2] 8b 92 [2] a5 92 [2] 9a 8e }

  condition:
    any of them
}