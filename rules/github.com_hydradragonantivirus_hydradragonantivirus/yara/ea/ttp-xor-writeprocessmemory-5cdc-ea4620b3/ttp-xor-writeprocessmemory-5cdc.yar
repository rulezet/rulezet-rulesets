rule TTP_XOR_WriteProcessMemory_5cdc {
  strings:
    $key_5cdc = { 0b ae [2] 39 8c [2] 3f b9 [2] 11 b9 [2] 2e a5 }

  condition:
    any of them
}