rule TTP_XOR_WriteProcessMemory_9199 {
  strings:
    $key_9199 = { c6 eb [2] f4 c9 [2] f2 fc [2] dc fc [2] e3 e0 }

  condition:
    any of them
}