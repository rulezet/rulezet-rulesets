rule TTP_XOR_WriteProcessMemory_29c3 {
  strings:
    $key_29c3 = { 7e b1 [2] 4c 93 [2] 4a a6 [2] 64 a6 [2] 5b ba }

  condition:
    any of them
}