rule TTP_XOR_WriteProcessMemory_655c {
  strings:
    $key_655c = { 32 2e [2] 00 0c [2] 06 39 [2] 28 39 [2] 17 25 }

  condition:
    any of them
}