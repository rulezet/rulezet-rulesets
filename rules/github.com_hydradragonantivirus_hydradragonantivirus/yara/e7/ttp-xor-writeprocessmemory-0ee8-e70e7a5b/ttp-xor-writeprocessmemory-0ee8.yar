rule TTP_XOR_WriteProcessMemory_0ee8 {
  strings:
    $key_0ee8 = { 59 9a [2] 6b b8 [2] 6d 8d [2] 43 8d [2] 7c 91 }

  condition:
    any of them
}