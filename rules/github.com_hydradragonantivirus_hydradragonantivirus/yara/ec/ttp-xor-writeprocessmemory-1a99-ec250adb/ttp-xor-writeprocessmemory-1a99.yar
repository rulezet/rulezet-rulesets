rule TTP_XOR_WriteProcessMemory_1a99 {
  strings:
    $key_1a99 = { 4d eb [2] 7f c9 [2] 79 fc [2] 57 fc [2] 68 e0 }

  condition:
    any of them
}