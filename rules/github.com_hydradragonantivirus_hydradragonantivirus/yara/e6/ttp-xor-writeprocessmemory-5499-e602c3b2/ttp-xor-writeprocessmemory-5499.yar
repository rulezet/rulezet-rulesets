rule TTP_XOR_WriteProcessMemory_5499 {
  strings:
    $key_5499 = { 03 eb [2] 31 c9 [2] 37 fc [2] 19 fc [2] 26 e0 }

  condition:
    any of them
}