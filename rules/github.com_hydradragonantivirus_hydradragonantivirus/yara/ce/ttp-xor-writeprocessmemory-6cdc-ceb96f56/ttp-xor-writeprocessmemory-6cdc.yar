rule TTP_XOR_WriteProcessMemory_6cdc {
  strings:
    $key_6cdc = { 3b ae [2] 09 8c [2] 0f b9 [2] 21 b9 [2] 1e a5 }

  condition:
    any of them
}