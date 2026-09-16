rule TTP_XOR_WriteProcessMemory_3cdc {
  strings:
    $key_3cdc = { 6b ae [2] 59 8c [2] 5f b9 [2] 71 b9 [2] 4e a5 }

  condition:
    any of them
}