rule TTP_XOR_WriteProcessMemory_7cdc {
  strings:
    $key_7cdc = { 2b ae [2] 19 8c [2] 1f b9 [2] 31 b9 [2] 0e a5 }

  condition:
    any of them
}