rule TTP_XOR_WriteProcessMemory_08c7 {
  strings:
    $key_08c7 = { 5f b5 [2] 6d 97 [2] 6b a2 [2] 45 a2 [2] 7a be }

  condition:
    any of them
}