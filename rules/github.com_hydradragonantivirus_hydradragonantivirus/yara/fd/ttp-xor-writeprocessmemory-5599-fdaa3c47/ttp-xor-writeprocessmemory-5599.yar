rule TTP_XOR_WriteProcessMemory_5599 {
  strings:
    $key_5599 = { 02 eb [2] 30 c9 [2] 36 fc [2] 18 fc [2] 27 e0 }

  condition:
    any of them
}