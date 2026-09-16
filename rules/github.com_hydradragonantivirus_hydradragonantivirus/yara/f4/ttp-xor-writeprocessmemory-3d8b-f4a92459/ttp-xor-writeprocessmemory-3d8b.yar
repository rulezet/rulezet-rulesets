rule TTP_XOR_WriteProcessMemory_3d8b {
  strings:
    $key_3d8b = { 6a f9 [2] 58 db [2] 5e ee [2] 70 ee [2] 4f f2 }

  condition:
    any of them
}