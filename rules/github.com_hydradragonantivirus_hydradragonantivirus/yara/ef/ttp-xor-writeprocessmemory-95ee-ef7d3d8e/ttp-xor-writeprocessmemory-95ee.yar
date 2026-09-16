rule TTP_XOR_WriteProcessMemory_95ee {
  strings:
    $key_95ee = { c2 9c [2] f0 be [2] f6 8b [2] d8 8b [2] e7 97 }

  condition:
    any of them
}