rule TTP_XOR_WriteProcessMemory_46bc {
  strings:
    $key_46bc = { 11 ce [2] 23 ec [2] 25 d9 [2] 0b d9 [2] 34 c5 }

  condition:
    any of them
}