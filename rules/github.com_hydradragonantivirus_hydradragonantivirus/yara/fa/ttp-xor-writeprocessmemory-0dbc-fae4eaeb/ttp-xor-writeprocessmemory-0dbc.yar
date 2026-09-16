rule TTP_XOR_WriteProcessMemory_0dbc {
  strings:
    $key_0dbc = { 5a ce [2] 68 ec [2] 6e d9 [2] 40 d9 [2] 7f c5 }

  condition:
    any of them
}