rule TTP_XOR_WriteProcessMemory_4199 {
  strings:
    $key_4199 = { 16 eb [2] 24 c9 [2] 22 fc [2] 0c fc [2] 33 e0 }

  condition:
    any of them
}