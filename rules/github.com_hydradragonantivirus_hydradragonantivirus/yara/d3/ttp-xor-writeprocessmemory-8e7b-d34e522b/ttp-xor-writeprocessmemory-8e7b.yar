rule TTP_XOR_WriteProcessMemory_8e7b {
  strings:
    $key_8e7b = { d9 09 [2] eb 2b [2] ed 1e [2] c3 1e [2] fc 02 }

  condition:
    any of them
}