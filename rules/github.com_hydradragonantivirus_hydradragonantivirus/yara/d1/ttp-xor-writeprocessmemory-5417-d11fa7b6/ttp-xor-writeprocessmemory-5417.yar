rule TTP_XOR_WriteProcessMemory_5417 {
  strings:
    $key_5417 = { 03 65 [2] 31 47 [2] 37 72 [2] 19 72 [2] 26 6e }

  condition:
    any of them
}