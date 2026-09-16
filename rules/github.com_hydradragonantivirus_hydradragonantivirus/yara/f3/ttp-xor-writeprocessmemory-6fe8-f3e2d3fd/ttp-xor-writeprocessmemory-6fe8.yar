rule TTP_XOR_WriteProcessMemory_6fe8 {
  strings:
    $key_6fe8 = { 38 9a [2] 0a b8 [2] 0c 8d [2] 22 8d [2] 1d 91 }

  condition:
    any of them
}