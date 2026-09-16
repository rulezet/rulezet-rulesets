rule TTP_XOR_WriteProcessMemory_f599 {
  strings:
    $key_f599 = { a2 eb [2] 90 c9 [2] 96 fc [2] b8 fc [2] 87 e0 }

  condition:
    any of them
}