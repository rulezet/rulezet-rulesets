rule TTP_XOR_WriteProcessMemory_32bc {
  strings:
    $key_32bc = { 65 ce [2] 57 ec [2] 51 d9 [2] 7f d9 [2] 40 c5 }

  condition:
    any of them
}