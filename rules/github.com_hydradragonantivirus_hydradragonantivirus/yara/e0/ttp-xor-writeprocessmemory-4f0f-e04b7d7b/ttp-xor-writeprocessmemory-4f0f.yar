rule TTP_XOR_WriteProcessMemory_4f0f {
  strings:
    $key_4f0f = { 18 7d [2] 2a 5f [2] 2c 6a [2] 02 6a [2] 3d 76 }

  condition:
    any of them
}