rule TTP_XOR_WriteProcessMemory_3007 {
  strings:
    $key_3007 = { 67 75 [2] 55 57 [2] 53 62 [2] 7d 62 [2] 42 7e }

  condition:
    any of them
}