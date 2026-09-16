rule TTP_XOR_WriteProcessMemory_4fcc {
  strings:
    $key_4fcc = { 18 be [2] 2a 9c [2] 2c a9 [2] 02 a9 [2] 3d b5 }

  condition:
    any of them
}