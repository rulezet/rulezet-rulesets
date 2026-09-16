rule TTP_XOR_WriteProcessMemory_099a {
  strings:
    $key_099a = { 5e e8 [2] 6c ca [2] 6a ff [2] 44 ff [2] 7b e3 }

  condition:
    any of them
}