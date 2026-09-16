rule TTP_XOR_WriteProcessMemory_3ff2 {
  strings:
    $key_3ff2 = { 68 80 [2] 5a a2 [2] 5c 97 [2] 72 97 [2] 4d 8b }

  condition:
    any of them
}