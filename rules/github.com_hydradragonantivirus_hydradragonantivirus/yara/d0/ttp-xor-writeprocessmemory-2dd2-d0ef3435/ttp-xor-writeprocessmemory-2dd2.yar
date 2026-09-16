rule TTP_XOR_WriteProcessMemory_2dd2 {
  strings:
    $key_2dd2 = { 7a a0 [2] 48 82 [2] 4e b7 [2] 60 b7 [2] 5f ab }

  condition:
    any of them
}