rule TTP_XOR_WriteProcessMemory_3fe8 {
  strings:
    $key_3fe8 = { 68 9a [2] 5a b8 [2] 5c 8d [2] 72 8d [2] 4d 91 }

  condition:
    any of them
}