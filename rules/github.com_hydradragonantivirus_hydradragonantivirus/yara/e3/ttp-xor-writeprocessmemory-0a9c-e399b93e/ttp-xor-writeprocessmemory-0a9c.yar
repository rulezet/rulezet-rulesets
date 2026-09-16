rule TTP_XOR_WriteProcessMemory_0a9c {
  strings:
    $key_0a9c = { 5d ee [2] 6f cc [2] 69 f9 [2] 47 f9 [2] 78 e5 }

  condition:
    any of them
}