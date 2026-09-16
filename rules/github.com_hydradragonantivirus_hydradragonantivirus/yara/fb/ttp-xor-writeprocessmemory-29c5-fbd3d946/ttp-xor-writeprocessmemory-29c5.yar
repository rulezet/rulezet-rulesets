rule TTP_XOR_WriteProcessMemory_29c5 {
  strings:
    $key_29c5 = { 7e b7 [2] 4c 95 [2] 4a a0 [2] 64 a0 [2] 5b bc }

  condition:
    any of them
}