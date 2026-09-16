rule TTP_XOR_WriteProcessMemory_5a4c {
  strings:
    $key_5a4c = { 0d 3e [2] 3f 1c [2] 39 29 [2] 17 29 [2] 28 35 }

  condition:
    any of them
}