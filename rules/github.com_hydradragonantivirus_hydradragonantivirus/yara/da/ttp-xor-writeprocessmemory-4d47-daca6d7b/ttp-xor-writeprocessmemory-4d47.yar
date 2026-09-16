rule TTP_XOR_WriteProcessMemory_4d47 {
  strings:
    $key_4d47 = { 1a 35 [2] 28 17 [2] 2e 22 [2] 00 22 [2] 3f 3e }

  condition:
    any of them
}