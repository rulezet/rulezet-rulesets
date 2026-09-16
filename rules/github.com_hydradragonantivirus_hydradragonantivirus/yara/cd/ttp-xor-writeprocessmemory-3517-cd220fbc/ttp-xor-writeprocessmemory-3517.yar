rule TTP_XOR_WriteProcessMemory_3517 {
  strings:
    $key_3517 = { 62 65 [2] 50 47 [2] 56 72 [2] 78 72 [2] 47 6e }

  condition:
    any of them
}