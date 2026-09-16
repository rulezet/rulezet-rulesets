rule TTP_XOR_WriteProcessMemory_b8b9 {
  strings:
    $key_b8b9 = { ef cb [2] dd e9 [2] db dc [2] f5 dc [2] ca c0 }

  condition:
    any of them
}