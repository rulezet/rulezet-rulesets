rule TTP_XOR_WriteProcessMemory_2f9c {
  strings:
    $key_2f9c = { 78 ee [2] 4a cc [2] 4c f9 [2] 62 f9 [2] 5d e5 }

  condition:
    any of them
}