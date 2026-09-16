rule TTP_XOR_WriteProcessMemory_0cdc {
  strings:
    $key_0cdc = { 5b ae [2] 69 8c [2] 6f b9 [2] 41 b9 [2] 7e a5 }

  condition:
    any of them
}