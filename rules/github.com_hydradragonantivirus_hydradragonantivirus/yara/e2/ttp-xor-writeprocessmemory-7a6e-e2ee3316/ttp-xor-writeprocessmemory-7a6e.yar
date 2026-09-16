rule TTP_XOR_WriteProcessMemory_7a6e {
  strings:
    $key_7a6e = { 2d 1c [2] 1f 3e [2] 19 0b [2] 37 0b [2] 08 17 }

  condition:
    any of them
}