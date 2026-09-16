rule TTP_XOR_WriteProcessMemory_92ee {
  strings:
    $key_92ee = { c5 9c [2] f7 be [2] f1 8b [2] df 8b [2] e0 97 }

  condition:
    any of them
}