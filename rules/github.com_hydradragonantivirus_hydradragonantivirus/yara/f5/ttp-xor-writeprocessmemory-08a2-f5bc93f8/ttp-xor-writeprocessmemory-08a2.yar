rule TTP_XOR_WriteProcessMemory_08a2 {
  strings:
    $key_08a2 = { 5f d0 [2] 6d f2 [2] 6b c7 [2] 45 c7 [2] 7a db }

  condition:
    any of them
}