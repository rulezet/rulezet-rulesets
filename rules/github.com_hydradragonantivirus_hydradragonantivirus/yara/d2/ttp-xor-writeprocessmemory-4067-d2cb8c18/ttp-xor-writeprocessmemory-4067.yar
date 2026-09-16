rule TTP_XOR_WriteProcessMemory_4067 {
  strings:
    $key_4067 = { 17 15 [2] 25 37 [2] 23 02 [2] 0d 02 [2] 32 1e }

  condition:
    any of them
}