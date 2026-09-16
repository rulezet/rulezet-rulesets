rule TTP_XOR_WriteProcessMemory_659c {
  strings:
    $key_659c = { 32 ee [2] 00 cc [2] 06 f9 [2] 28 f9 [2] 17 e5 }

  condition:
    any of them
}