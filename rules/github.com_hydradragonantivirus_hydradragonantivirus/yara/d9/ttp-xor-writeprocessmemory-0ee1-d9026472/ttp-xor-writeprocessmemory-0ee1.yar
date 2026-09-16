rule TTP_XOR_WriteProcessMemory_0ee1 {
  strings:
    $key_0ee1 = { 59 93 [2] 6b b1 [2] 6d 84 [2] 43 84 [2] 7c 98 }

  condition:
    any of them
}