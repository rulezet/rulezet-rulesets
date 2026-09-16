rule TTP_XOR_WriteProcessMemory_927f {
  strings:
    $key_927f = { c5 0d [2] f7 2f [2] f1 1a [2] df 1a [2] e0 06 }

  condition:
    any of them
}