rule TTP_XOR_WriteProcessMemory_e6bc {
  strings:
    $key_e6bc = { b1 ce [2] 83 ec [2] 85 d9 [2] ab d9 [2] 94 c5 }

  condition:
    any of them
}