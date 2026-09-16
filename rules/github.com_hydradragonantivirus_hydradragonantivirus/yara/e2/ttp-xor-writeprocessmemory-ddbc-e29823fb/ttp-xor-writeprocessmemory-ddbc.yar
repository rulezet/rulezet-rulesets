rule TTP_XOR_WriteProcessMemory_ddbc {
  strings:
    $key_ddbc = { 8a ce [2] b8 ec [2] be d9 [2] 90 d9 [2] af c5 }

  condition:
    any of them
}