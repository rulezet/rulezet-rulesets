rule TTP_XOR_WriteProcessMemory_014c {
  strings:
    $key_014c = { 56 3e [2] 64 1c [2] 62 29 [2] 4c 29 [2] 73 35 }

  condition:
    any of them
}