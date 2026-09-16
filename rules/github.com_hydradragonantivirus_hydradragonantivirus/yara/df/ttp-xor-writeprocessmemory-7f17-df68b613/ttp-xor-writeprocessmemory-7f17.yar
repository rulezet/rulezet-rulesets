rule TTP_XOR_WriteProcessMemory_7f17 {
  strings:
    $key_7f17 = { 28 65 [2] 1a 47 [2] 1c 72 [2] 32 72 [2] 0d 6e }

  condition:
    any of them
}