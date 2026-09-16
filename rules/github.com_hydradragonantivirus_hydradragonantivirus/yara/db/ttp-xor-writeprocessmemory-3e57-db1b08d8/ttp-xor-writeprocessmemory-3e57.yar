rule TTP_XOR_WriteProcessMemory_3e57 {
  strings:
    $key_3e57 = { 69 25 [2] 5b 07 [2] 5d 32 [2] 73 32 [2] 4c 2e }

  condition:
    any of them
}