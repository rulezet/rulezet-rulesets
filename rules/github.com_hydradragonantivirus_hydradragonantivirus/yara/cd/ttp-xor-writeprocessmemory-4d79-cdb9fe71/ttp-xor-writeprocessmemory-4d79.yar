rule TTP_XOR_WriteProcessMemory_4d79 {
  strings:
    $key_4d79 = { 1a 0b [2] 28 29 [2] 2e 1c [2] 00 1c [2] 3f 00 }

  condition:
    any of them
}