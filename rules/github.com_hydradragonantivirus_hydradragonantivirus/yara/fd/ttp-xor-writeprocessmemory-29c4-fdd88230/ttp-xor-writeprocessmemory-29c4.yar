rule TTP_XOR_WriteProcessMemory_29c4 {
  strings:
    $key_29c4 = { 7e b6 [2] 4c 94 [2] 4a a1 [2] 64 a1 [2] 5b bd }

  condition:
    any of them
}