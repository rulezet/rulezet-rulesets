rule TTP_XOR_WriteProcessMemory_2b99 {
  strings:
    $key_2b99 = { 7c eb [2] 4e c9 [2] 48 fc [2] 66 fc [2] 59 e0 }

  condition:
    any of them
}