rule TTP_XOR_WriteProcessMemory_1d47 {
  strings:
    $key_1d47 = { 4a 35 [2] 78 17 [2] 7e 22 [2] 50 22 [2] 6f 3e }

  condition:
    any of them
}