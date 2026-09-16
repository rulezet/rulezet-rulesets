rule TTP_XOR_WriteProcessMemory_652c {
  strings:
    $key_652c = { 32 5e [2] 00 7c [2] 06 49 [2] 28 49 [2] 17 55 }

  condition:
    any of them
}