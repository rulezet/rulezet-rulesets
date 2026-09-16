rule TTP_XOR_WriteProcessMemory_4f6a {
  strings:
    $key_4f6a = { 18 18 [2] 2a 3a [2] 2c 0f [2] 02 0f [2] 3d 13 }

  condition:
    any of them
}