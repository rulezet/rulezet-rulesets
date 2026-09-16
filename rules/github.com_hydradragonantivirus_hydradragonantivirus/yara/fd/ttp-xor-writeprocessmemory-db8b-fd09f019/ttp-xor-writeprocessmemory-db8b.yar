rule TTP_XOR_WriteProcessMemory_db8b {
  strings:
    $key_db8b = { 8c f9 [2] be db [2] b8 ee [2] 96 ee [2] a9 f2 }

  condition:
    any of them
}