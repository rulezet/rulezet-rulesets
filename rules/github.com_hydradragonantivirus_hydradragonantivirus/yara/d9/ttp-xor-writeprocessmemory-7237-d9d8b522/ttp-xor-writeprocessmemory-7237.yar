rule TTP_XOR_WriteProcessMemory_7237 {
  strings:
    $key_7237 = { 25 45 [2] 17 67 [2] 11 52 [2] 3f 52 [2] 00 4e }

  condition:
    any of them
}