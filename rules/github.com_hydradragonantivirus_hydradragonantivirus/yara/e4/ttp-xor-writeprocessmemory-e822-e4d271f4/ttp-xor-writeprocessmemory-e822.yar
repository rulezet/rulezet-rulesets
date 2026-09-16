rule TTP_XOR_WriteProcessMemory_e822 {
  strings:
    $key_e822 = { bf 50 [2] 8d 72 [2] 8b 47 [2] a5 47 [2] 9a 5b }

  condition:
    any of them
}