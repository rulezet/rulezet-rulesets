rule TTP_XOR_WriteProcessMemory_0a99 {
  strings:
    $key_0a99 = { 5d eb [2] 6f c9 [2] 69 fc [2] 47 fc [2] 78 e0 }

  condition:
    any of them
}