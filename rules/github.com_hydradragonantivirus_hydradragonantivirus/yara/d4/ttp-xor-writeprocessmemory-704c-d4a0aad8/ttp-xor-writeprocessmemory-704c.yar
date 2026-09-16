rule TTP_XOR_WriteProcessMemory_704c {
  strings:
    $key_704c = { 27 3e [2] 15 1c [2] 13 29 [2] 3d 29 [2] 02 35 }

  condition:
    any of them
}