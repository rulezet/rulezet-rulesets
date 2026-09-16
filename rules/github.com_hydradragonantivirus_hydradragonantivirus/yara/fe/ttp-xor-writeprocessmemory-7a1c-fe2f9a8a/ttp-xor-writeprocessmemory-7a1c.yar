rule TTP_XOR_WriteProcessMemory_7a1c {
  strings:
    $key_7a1c = { 2d 6e [2] 1f 4c [2] 19 79 [2] 37 79 [2] 08 65 }

  condition:
    any of them
}