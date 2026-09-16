rule TTP_XOR_WriteProcessMemory_75bc {
  strings:
    $key_75bc = { 22 ce [2] 10 ec [2] 16 d9 [2] 38 d9 [2] 07 c5 }

  condition:
    any of them
}