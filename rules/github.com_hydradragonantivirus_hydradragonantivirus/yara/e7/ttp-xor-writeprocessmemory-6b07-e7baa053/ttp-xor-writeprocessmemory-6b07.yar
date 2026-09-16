rule TTP_XOR_WriteProcessMemory_6b07 {
  strings:
    $key_6b07 = { 3c 75 [2] 0e 57 [2] 08 62 [2] 26 62 [2] 19 7e }

  condition:
    any of them
}