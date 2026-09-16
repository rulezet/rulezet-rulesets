rule TTP_XOR_WriteProcessMemory_29f2 {
  strings:
    $key_29f2 = { 7e 80 [2] 4c a2 [2] 4a 97 [2] 64 97 [2] 5b 8b }

  condition:
    any of them
}