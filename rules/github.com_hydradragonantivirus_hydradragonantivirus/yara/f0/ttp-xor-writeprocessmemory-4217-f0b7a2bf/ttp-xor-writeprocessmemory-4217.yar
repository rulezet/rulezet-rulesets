rule TTP_XOR_WriteProcessMemory_4217 {
  strings:
    $key_4217 = { 15 65 [2] 27 47 [2] 21 72 [2] 0f 72 [2] 30 6e }

  condition:
    any of them
}