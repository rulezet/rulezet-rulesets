rule TTP_XOR_WriteProcessMemory_81be {
  strings:
    $key_81be = { d6 cc [2] e4 ee [2] e2 db [2] cc db [2] f3 c7 }

  condition:
    any of them
}