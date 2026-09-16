rule TTP_XOR_WriteProcessMemory_19c7 {
  strings:
    $key_19c7 = { 4e b5 [2] 7c 97 [2] 7a a2 [2] 54 a2 [2] 6b be }

  condition:
    any of them
}