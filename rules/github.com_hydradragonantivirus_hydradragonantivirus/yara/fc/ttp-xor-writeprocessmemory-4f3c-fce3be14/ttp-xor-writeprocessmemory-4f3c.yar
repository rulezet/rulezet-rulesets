rule TTP_XOR_WriteProcessMemory_4f3c {
  strings:
    $key_4f3c = { 18 4e [2] 2a 6c [2] 2c 59 [2] 02 59 [2] 3d 45 }

  condition:
    any of them
}