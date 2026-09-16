rule TTP_XOR_WriteProcessMemory_a3bc {
  strings:
    $key_a3bc = { f4 ce [2] c6 ec [2] c0 d9 [2] ee d9 [2] d1 c5 }

  condition:
    any of them
}