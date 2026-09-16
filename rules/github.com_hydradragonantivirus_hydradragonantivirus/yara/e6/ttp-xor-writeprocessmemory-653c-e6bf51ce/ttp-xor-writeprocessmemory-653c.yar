rule TTP_XOR_WriteProcessMemory_653c {
  strings:
    $key_653c = { 32 4e [2] 00 6c [2] 06 59 [2] 28 59 [2] 17 45 }

  condition:
    any of them
}