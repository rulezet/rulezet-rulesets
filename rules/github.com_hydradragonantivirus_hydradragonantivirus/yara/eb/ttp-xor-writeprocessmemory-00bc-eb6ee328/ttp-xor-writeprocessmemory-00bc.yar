rule TTP_XOR_WriteProcessMemory_00bc {
  strings:
    $key_00bc = { 57 ce [2] 65 ec [2] 63 d9 [2] 4d d9 [2] 72 c5 }

  condition:
    any of them
}