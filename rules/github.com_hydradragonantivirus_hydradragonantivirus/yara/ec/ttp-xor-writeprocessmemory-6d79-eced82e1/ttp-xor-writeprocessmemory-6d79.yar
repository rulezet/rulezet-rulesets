rule TTP_XOR_WriteProcessMemory_6d79 {
  strings:
    $key_6d79 = { 3a 0b [2] 08 29 [2] 0e 1c [2] 20 1c [2] 1f 00 }

  condition:
    any of them
}