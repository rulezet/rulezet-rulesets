rule TTP_XOR_WriteProcessMemory_c99c {
  strings:
    $key_c99c = { 9e ee [2] ac cc [2] aa f9 [2] 84 f9 [2] bb e5 }

  condition:
    any of them
}