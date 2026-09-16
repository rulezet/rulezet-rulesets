rule TTP_XOR_WriteProcessMemory_f5bc {
  strings:
    $key_f5bc = { a2 ce [2] 90 ec [2] 96 d9 [2] b8 d9 [2] 87 c5 }

  condition:
    any of them
}