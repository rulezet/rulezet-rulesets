rule TTP_XOR_WriteProcessMemory_6f17 {
  strings:
    $key_6f17 = { 38 65 [2] 0a 47 [2] 0c 72 [2] 22 72 [2] 1d 6e }

  condition:
    any of them
}