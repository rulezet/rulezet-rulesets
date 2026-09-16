rule TTP_XOR_WriteProcessMemory_4157 {
  strings:
    $key_4157 = { 16 25 [2] 24 07 [2] 22 32 [2] 0c 32 [2] 33 2e }

  condition:
    any of them
}