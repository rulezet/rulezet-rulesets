rule TTP_XOR_WriteProcessMemory_7a3c {
  strings:
    $key_7a3c = { 2d 4e [2] 1f 6c [2] 19 59 [2] 37 59 [2] 08 45 }

  condition:
    any of them
}