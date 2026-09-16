rule TTP_XOR_WriteProcessMemory_870c {
  strings:
    $key_870c = { d0 7e [2] e2 5c [2] e4 69 [2] ca 69 [2] f5 75 }

  condition:
    any of them
}