rule TTP_XOR_WriteProcessMemory_048b {
  strings:
    $key_048b = { 53 f9 [2] 61 db [2] 67 ee [2] 49 ee [2] 76 f2 }

  condition:
    any of them
}