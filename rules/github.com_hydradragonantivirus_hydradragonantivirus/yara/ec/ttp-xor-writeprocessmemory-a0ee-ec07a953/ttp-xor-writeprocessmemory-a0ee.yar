rule TTP_XOR_WriteProcessMemory_a0ee {
  strings:
    $key_a0ee = { f7 9c [2] c5 be [2] c3 8b [2] ed 8b [2] d2 97 }

  condition:
    any of them
}