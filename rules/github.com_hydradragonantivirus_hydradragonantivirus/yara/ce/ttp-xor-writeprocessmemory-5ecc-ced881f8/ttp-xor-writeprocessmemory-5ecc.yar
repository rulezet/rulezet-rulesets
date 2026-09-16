rule TTP_XOR_WriteProcessMemory_5ecc {
  strings:
    $key_5ecc = { 09 be [2] 3b 9c [2] 3d a9 [2] 13 a9 [2] 2c b5 }

  condition:
    any of them
}