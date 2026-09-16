rule TTP_XOR_WriteProcessMemory_1699 {
  strings:
    $key_1699 = { 41 eb [2] 73 c9 [2] 75 fc [2] 5b fc [2] 64 e0 }

  condition:
    any of them
}