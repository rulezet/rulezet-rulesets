rule TTP_XOR_WriteProcessMemory_92e8 {
  strings:
    $key_92e8 = { c5 9a [2] f7 b8 [2] f1 8d [2] df 8d [2] e0 91 }

  condition:
    any of them
}