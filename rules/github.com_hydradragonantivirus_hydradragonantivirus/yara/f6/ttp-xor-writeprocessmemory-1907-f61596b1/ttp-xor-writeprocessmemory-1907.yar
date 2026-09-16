rule TTP_XOR_WriteProcessMemory_1907 {
  strings:
    $key_1907 = { 4e 75 [2] 7c 57 [2] 7a 62 [2] 54 62 [2] 6b 7e }

  condition:
    any of them
}