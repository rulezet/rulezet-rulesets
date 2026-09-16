rule TTP_XOR_WriteProcessMemory_518b {
  strings:
    $key_518b = { 06 f9 [2] 34 db [2] 32 ee [2] 1c ee [2] 23 f2 }

  condition:
    any of them
}