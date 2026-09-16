rule TTP_XOR_WriteProcessMemory_e842 {
  strings:
    $key_e842 = { bf 30 [2] 8d 12 [2] 8b 27 [2] a5 27 [2] 9a 3b }

  condition:
    any of them
}