rule TTP_XOR_WriteProcessMemory_2c2d {
  strings:
    $key_2c2d = { 7b 5f [2] 49 7d [2] 4f 48 [2] 61 48 [2] 5e 54 }

  condition:
    any of them
}