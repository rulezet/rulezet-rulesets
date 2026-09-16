rule TTP_XOR_WriteProcessMemory_252c {
  strings:
    $key_252c = { 72 5e [2] 40 7c [2] 46 49 [2] 68 49 [2] 57 55 }

  condition:
    any of them
}