rule TTP_XOR_WriteProcessMemory_5eca {
  strings:
    $key_5eca = { 09 b8 [2] 3b 9a [2] 3d af [2] 13 af [2] 2c b3 }

  condition:
    any of them
}