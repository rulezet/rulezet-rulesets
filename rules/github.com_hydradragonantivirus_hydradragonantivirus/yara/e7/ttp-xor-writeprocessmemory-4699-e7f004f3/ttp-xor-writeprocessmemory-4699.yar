rule TTP_XOR_WriteProcessMemory_4699 {
  strings:
    $key_4699 = { 11 eb [2] 23 c9 [2] 25 fc [2] 0b fc [2] 34 e0 }

  condition:
    any of them
}