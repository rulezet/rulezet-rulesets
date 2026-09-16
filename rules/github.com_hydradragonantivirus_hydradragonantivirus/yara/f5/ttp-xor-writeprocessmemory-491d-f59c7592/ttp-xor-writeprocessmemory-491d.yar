rule TTP_XOR_WriteProcessMemory_491d {
  strings:
    $key_491d = { 1e 6f [2] 2c 4d [2] 2a 78 [2] 04 78 [2] 3b 64 }

  condition:
    any of them
}