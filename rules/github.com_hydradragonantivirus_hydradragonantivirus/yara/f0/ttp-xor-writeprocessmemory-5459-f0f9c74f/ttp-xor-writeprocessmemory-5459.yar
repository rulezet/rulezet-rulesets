rule TTP_XOR_WriteProcessMemory_5459 {
  strings:
    $key_5459 = { 03 2b [2] 31 09 [2] 37 3c [2] 19 3c [2] 26 20 }

  condition:
    any of them
}