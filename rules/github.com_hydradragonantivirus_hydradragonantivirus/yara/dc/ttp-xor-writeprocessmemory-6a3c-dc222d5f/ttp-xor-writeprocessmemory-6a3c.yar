rule TTP_XOR_WriteProcessMemory_6a3c {
  strings:
    $key_6a3c = { 3d 4e [2] 0f 6c [2] 09 59 [2] 27 59 [2] 18 45 }

  condition:
    any of them
}