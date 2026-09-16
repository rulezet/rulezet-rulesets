rule TTP_XOR_WriteProcessMemory_4fdd {
  strings:
    $key_4fdd = { 18 af [2] 2a 8d [2] 2c b8 [2] 02 b8 [2] 3d a4 }

  condition:
    any of them
}