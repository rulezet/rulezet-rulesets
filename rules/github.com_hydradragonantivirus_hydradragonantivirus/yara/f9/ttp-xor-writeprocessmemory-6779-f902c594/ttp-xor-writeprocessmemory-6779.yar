rule TTP_XOR_WriteProcessMemory_6779 {
  strings:
    $key_6779 = { 30 0b [2] 02 29 [2] 04 1c [2] 2a 1c [2] 15 00 }

  condition:
    any of them
}