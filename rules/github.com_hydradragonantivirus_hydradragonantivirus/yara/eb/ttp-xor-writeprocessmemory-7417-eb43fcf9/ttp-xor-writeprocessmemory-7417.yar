rule TTP_XOR_WriteProcessMemory_7417 {
  strings:
    $key_7417 = { 23 65 [2] 11 47 [2] 17 72 [2] 39 72 [2] 06 6e }

  condition:
    any of them
}