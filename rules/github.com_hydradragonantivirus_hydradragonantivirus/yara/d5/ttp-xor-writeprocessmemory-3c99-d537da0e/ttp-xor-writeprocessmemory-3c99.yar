rule TTP_XOR_WriteProcessMemory_3c99 {
  strings:
    $key_3c99 = { 6b eb [2] 59 c9 [2] 5f fc [2] 71 fc [2] 4e e0 }

  condition:
    any of them
}