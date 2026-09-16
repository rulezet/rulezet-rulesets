rule TTP_XOR_WriteProcessMemory_9101 {
  strings:
    $key_9101 = { c6 73 [2] f4 51 [2] f2 64 [2] dc 64 [2] e3 78 }

  condition:
    any of them
}