rule TTP_XOR_WriteProcessMemory_6417 {
  strings:
    $key_6417 = { 33 65 [2] 01 47 [2] 07 72 [2] 29 72 [2] 16 6e }

  condition:
    any of them
}