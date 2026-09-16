rule TTP_XOR_WriteProcessMemory_7e57 {
  strings:
    $key_7e57 = { 29 25 [2] 1b 07 [2] 1d 32 [2] 33 32 [2] 0c 2e }

  condition:
    any of them
}