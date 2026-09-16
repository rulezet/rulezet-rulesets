rule TTP_XOR_WriteProcessMemory_658b {
  strings:
    $key_658b = { 32 f9 [2] 00 db [2] 06 ee [2] 28 ee [2] 17 f2 }

  condition:
    any of them
}