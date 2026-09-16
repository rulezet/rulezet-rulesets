rule TTP_XOR_WriteProcessMemory_e0ee {
  strings:
    $key_e0ee = { b7 9c [2] 85 be [2] 83 8b [2] ad 8b [2] 92 97 }

  condition:
    any of them
}