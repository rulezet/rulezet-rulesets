rule TTP_XOR_WriteProcessMemory_41e8 {
  strings:
    $key_41e8 = { 16 9a [2] 24 b8 [2] 22 8d [2] 0c 8d [2] 33 91 }

  condition:
    any of them
}