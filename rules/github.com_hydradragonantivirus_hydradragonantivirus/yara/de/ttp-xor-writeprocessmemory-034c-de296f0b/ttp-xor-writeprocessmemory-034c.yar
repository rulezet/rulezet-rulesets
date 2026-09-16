rule TTP_XOR_WriteProcessMemory_034c {
  strings:
    $key_034c = { 54 3e [2] 66 1c [2] 60 29 [2] 4e 29 [2] 71 35 }

  condition:
    any of them
}