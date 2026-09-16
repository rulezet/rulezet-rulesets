rule TTP_XOR_WriteProcessMemory_0957 {
  strings:
    $key_0957 = { 5e 25 [2] 6c 07 [2] 6a 32 [2] 44 32 [2] 7b 2e }

  condition:
    any of them
}