rule TTP_XOR_WriteProcessMemory_611d {
  strings:
    $key_611d = { 36 6f [2] 04 4d [2] 02 78 [2] 2c 78 [2] 13 64 }

  condition:
    any of them
}