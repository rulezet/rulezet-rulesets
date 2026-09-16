rule TTP_XOR_WriteProcessMemory_5b99 {
  strings:
    $key_5b99 = { 0c eb [2] 3e c9 [2] 38 fc [2] 16 fc [2] 29 e0 }

  condition:
    any of them
}