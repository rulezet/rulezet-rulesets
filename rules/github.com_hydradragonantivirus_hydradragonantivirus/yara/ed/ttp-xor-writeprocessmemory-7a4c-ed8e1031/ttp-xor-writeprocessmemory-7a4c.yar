rule TTP_XOR_WriteProcessMemory_7a4c {
  strings:
    $key_7a4c = { 2d 3e [2] 1f 1c [2] 19 29 [2] 37 29 [2] 08 35 }

  condition:
    any of them
}