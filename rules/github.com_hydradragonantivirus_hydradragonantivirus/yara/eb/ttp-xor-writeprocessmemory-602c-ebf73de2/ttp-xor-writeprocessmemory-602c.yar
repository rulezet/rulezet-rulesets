rule TTP_XOR_WriteProcessMemory_602c {
  strings:
    $key_602c = { 37 5e [2] 05 7c [2] 03 49 [2] 2d 49 [2] 12 55 }

  condition:
    any of them
}