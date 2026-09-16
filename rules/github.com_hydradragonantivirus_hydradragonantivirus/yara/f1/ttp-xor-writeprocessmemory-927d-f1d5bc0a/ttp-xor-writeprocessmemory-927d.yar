rule TTP_XOR_WriteProcessMemory_927d {
  strings:
    $key_927d = { c5 0f [2] f7 2d [2] f1 18 [2] df 18 [2] e0 04 }

  condition:
    any of them
}