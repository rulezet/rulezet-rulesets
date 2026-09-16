rule TTP_XOR_WriteProcessMemory_4fcd {
  strings:
    $key_4fcd = { 18 bf [2] 2a 9d [2] 2c a8 [2] 02 a8 [2] 3d b4 }

  condition:
    any of them
}