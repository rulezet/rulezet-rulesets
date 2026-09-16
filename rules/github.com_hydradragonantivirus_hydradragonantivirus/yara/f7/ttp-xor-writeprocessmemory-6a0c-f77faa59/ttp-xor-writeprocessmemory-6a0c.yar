rule TTP_XOR_WriteProcessMemory_6a0c {
  strings:
    $key_6a0c = { 3d 7e [2] 0f 5c [2] 09 69 [2] 27 69 [2] 18 75 }

  condition:
    any of them
}