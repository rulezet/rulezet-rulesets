rule TTP_XOR_WriteProcessMemory_6499 {
  strings:
    $key_6499 = { 33 eb [2] 01 c9 [2] 07 fc [2] 29 fc [2] 16 e0 }

  condition:
    any of them
}