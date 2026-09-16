rule TTP_XOR_WriteProcessMemory_3a99 {
  strings:
    $key_3a99 = { 6d eb [2] 5f c9 [2] 59 fc [2] 77 fc [2] 48 e0 }

  condition:
    any of them
}