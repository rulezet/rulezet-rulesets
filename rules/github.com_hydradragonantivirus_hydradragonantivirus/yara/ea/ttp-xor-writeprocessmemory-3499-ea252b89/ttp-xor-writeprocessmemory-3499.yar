rule TTP_XOR_WriteProcessMemory_3499 {
  strings:
    $key_3499 = { 63 eb [2] 51 c9 [2] 57 fc [2] 79 fc [2] 46 e0 }

  condition:
    any of them
}