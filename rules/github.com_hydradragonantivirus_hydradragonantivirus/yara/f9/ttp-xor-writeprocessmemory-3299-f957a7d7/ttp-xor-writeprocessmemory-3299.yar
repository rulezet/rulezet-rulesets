rule TTP_XOR_WriteProcessMemory_3299 {
  strings:
    $key_3299 = { 65 eb [2] 57 c9 [2] 51 fc [2] 7f fc [2] 40 e0 }

  condition:
    any of them
}