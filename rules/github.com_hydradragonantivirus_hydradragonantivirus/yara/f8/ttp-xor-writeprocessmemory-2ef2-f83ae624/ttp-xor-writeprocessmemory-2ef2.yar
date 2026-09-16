rule TTP_XOR_WriteProcessMemory_2ef2 {
  strings:
    $key_2ef2 = { 79 80 [2] 4b a2 [2] 4d 97 [2] 63 97 [2] 5c 8b }

  condition:
    any of them
}