rule TTP_XOR_WriteProcessMemory_7dd7 {
  strings:
    $key_7dd7 = { 2a a5 [2] 18 87 [2] 1e b2 [2] 30 b2 [2] 0f ae }

  condition:
    any of them
}