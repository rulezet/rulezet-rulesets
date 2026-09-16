rule TTP_XOR_WriteProcessMemory_7a99 {
  strings:
    $key_7a99 = { 2d eb [2] 1f c9 [2] 19 fc [2] 37 fc [2] 08 e0 }

  condition:
    any of them
}