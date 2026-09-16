rule TTP_XOR_WriteProcessMemory_0953 {
  strings:
    $key_0953 = { 5e 21 [2] 6c 03 [2] 6a 36 [2] 44 36 [2] 7b 2a }

  condition:
    any of them
}