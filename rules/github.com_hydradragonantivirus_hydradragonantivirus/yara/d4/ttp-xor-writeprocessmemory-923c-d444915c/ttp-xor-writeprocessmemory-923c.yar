rule TTP_XOR_WriteProcessMemory_923c {
  strings:
    $key_923c = { c5 4e [2] f7 6c [2] f1 59 [2] df 59 [2] e0 45 }

  condition:
    any of them
}