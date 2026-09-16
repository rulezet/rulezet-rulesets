rule TTP_XOR_WriteProcessMemory_7dbe {
  strings:
    $key_7dbe = { 2a cc [2] 18 ee [2] 1e db [2] 30 db [2] 0f c7 }

  condition:
    any of them
}