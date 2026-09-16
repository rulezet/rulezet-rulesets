rule TTP_XOR_WriteProcessMemory_4c07 {
  strings:
    $key_4c07 = { 1b 75 [2] 29 57 [2] 2f 62 [2] 01 62 [2] 3e 7e }

  condition:
    any of them
}