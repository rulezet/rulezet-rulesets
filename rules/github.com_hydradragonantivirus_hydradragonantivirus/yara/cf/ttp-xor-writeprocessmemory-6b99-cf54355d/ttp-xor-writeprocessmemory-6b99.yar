rule TTP_XOR_WriteProcessMemory_6b99 {
  strings:
    $key_6b99 = { 3c eb [2] 0e c9 [2] 08 fc [2] 26 fc [2] 19 e0 }

  condition:
    any of them
}