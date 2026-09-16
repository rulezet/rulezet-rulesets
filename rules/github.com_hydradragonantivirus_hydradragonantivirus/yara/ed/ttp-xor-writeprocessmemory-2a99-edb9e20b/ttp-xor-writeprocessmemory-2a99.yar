rule TTP_XOR_WriteProcessMemory_2a99 {
  strings:
    $key_2a99 = { 7d eb [2] 4f c9 [2] 49 fc [2] 67 fc [2] 58 e0 }

  condition:
    any of them
}