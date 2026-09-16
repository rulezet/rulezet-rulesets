rule TTP_XOR_WriteProcessMemory_089c {
  strings:
    $key_089c = { 5f ee [2] 6d cc [2] 6b f9 [2] 45 f9 [2] 7a e5 }

  condition:
    any of them
}