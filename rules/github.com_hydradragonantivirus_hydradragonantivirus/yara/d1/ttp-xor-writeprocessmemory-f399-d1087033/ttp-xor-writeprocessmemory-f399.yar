rule TTP_XOR_WriteProcessMemory_f399 {
  strings:
    $key_f399 = { a4 eb [2] 96 c9 [2] 90 fc [2] be fc [2] 81 e0 }

  condition:
    any of them
}