rule TTP_XOR_WriteProcessMemory_d99c {
  strings:
    $key_d99c = { 8e ee [2] bc cc [2] ba f9 [2] 94 f9 [2] ab e5 }

  condition:
    any of them
}