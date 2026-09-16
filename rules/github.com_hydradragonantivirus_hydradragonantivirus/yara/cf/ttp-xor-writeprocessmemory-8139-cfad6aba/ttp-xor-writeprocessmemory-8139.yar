rule TTP_XOR_WriteProcessMemory_8139 {
  strings:
    $key_8139 = { d6 4b [2] e4 69 [2] e2 5c [2] cc 5c [2] f3 40 }

  condition:
    any of them
}