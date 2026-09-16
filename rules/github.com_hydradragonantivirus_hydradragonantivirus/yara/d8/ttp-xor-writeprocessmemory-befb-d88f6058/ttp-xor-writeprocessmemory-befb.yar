rule TTP_XOR_WriteProcessMemory_befb {
  strings:
    $key_befb = { e9 89 [2] db ab [2] dd 9e [2] f3 9e [2] cc 82 }

  condition:
    any of them
}