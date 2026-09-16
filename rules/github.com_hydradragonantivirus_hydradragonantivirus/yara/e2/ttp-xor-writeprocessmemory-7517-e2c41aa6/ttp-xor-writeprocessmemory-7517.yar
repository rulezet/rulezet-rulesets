rule TTP_XOR_WriteProcessMemory_7517 {
  strings:
    $key_7517 = { 22 65 [2] 10 47 [2] 16 72 [2] 38 72 [2] 07 6e }

  condition:
    any of them
}