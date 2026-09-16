rule TTP_XOR_WriteProcessMemory_254c {
  strings:
    $key_254c = { 72 3e [2] 40 1c [2] 46 29 [2] 68 29 [2] 57 35 }

  condition:
    any of them
}