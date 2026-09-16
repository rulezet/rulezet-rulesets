rule TTP_XOR_WriteProcessMemory_09bc {
  strings:
    $key_09bc = { 5e ce [2] 6c ec [2] 6a d9 [2] 44 d9 [2] 7b c5 }

  condition:
    any of them
}