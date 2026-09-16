rule TTP_XOR_WriteProcessMemory_4917 {
  strings:
    $key_4917 = { 1e 65 [2] 2c 47 [2] 2a 72 [2] 04 72 [2] 3b 6e }

  condition:
    any of them
}