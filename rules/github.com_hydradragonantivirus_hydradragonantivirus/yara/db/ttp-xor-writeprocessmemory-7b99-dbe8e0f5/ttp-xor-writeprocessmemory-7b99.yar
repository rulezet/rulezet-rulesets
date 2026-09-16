rule TTP_XOR_WriteProcessMemory_7b99 {
  strings:
    $key_7b99 = { 2c eb [2] 1e c9 [2] 18 fc [2] 36 fc [2] 09 e0 }

  condition:
    any of them
}