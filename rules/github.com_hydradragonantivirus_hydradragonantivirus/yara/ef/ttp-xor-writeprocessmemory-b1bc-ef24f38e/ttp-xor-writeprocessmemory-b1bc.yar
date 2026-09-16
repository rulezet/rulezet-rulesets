rule TTP_XOR_WriteProcessMemory_b1bc {
  strings:
    $key_b1bc = { e6 ce [2] d4 ec [2] d2 d9 [2] fc d9 [2] c3 c5 }

  condition:
    any of them
}