rule TTP_XOR_WriteProcessMemory_703c {
  strings:
    $key_703c = { 27 4e [2] 15 6c [2] 13 59 [2] 3d 59 [2] 02 45 }

  condition:
    any of them
}