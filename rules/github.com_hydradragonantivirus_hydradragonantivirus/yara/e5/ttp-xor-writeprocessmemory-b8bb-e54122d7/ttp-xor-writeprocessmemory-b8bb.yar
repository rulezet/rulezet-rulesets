rule TTP_XOR_WriteProcessMemory_b8bb {
  strings:
    $key_b8bb = { ef c9 [2] dd eb [2] db de [2] f5 de [2] ca c2 }

  condition:
    any of them
}