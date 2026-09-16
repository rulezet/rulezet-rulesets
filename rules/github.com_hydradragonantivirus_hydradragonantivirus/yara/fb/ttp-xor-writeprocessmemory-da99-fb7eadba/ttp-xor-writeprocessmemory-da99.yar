rule TTP_XOR_WriteProcessMemory_da99 {
  strings:
    $key_da99 = { 8d eb [2] bf c9 [2] b9 fc [2] 97 fc [2] a8 e0 }

  condition:
    any of them
}