rule TTP_XOR_WriteProcessMemory_b8dc {
  strings:
    $key_b8dc = { ef ae [2] dd 8c [2] db b9 [2] f5 b9 [2] ca a5 }

  condition:
    any of them
}