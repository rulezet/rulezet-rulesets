rule TTP_XOR_WriteProcessMemory_3b47 {
  strings:
    $key_3b47 = { 6c 35 [2] 5e 17 [2] 58 22 [2] 76 22 [2] 49 3e }

  condition:
    any of them
}