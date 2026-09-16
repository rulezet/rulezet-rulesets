rule TTP_XOR_WriteProcessMemory_6599 {
  strings:
    $key_6599 = { 32 eb [2] 00 c9 [2] 06 fc [2] 28 fc [2] 17 e0 }

  condition:
    any of them
}