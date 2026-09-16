rule TTP_XOR_WriteProcessMemory_298b {
  strings:
    $key_298b = { 7e f9 [2] 4c db [2] 4a ee [2] 64 ee [2] 5b f2 }

  condition:
    any of them
}