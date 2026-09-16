rule TTP_XOR_WriteProcessMemory_a1bc {
  strings:
    $key_a1bc = { f6 ce [2] c4 ec [2] c2 d9 [2] ec d9 [2] d3 c5 }

  condition:
    any of them
}