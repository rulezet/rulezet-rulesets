rule TTP_XOR_WriteProcessMemory_f5e9 {
  strings:
    $key_f5e9 = { a2 9b [2] 90 b9 [2] 96 8c [2] b8 8c [2] 87 90 }

  condition:
    any of them
}