rule TTP_XOR_WriteProcessMemory_5d47 {
  strings:
    $key_5d47 = { 0a 35 [2] 38 17 [2] 3e 22 [2] 10 22 [2] 2f 3e }

  condition:
    any of them
}