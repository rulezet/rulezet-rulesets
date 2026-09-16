rule TTP_XOR_WriteProcessMemory_1817 {
  strings:
    $key_1817 = { 4f 65 [2] 7d 47 [2] 7b 72 [2] 55 72 [2] 6a 6e }

  condition:
    any of them
}