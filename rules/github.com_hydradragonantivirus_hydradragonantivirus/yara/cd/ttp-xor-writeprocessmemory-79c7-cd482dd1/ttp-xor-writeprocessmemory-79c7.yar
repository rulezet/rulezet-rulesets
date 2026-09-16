rule TTP_XOR_WriteProcessMemory_79c7 {
  strings:
    $key_79c7 = { 2e b5 [2] 1c 97 [2] 1a a2 [2] 34 a2 [2] 0b be }

  condition:
    any of them
}