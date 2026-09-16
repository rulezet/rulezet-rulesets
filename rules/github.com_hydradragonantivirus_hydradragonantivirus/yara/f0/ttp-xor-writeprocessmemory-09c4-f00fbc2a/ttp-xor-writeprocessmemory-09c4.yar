rule TTP_XOR_WriteProcessMemory_09c4 {
  strings:
    $key_09c4 = { 5e b6 [2] 6c 94 [2] 6a a1 [2] 44 a1 [2] 7b bd }

  condition:
    any of them
}