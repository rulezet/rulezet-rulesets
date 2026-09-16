rule TTP_XOR_WriteProcessMemory_5e6a {
  strings:
    $key_5e6a = { 09 18 [2] 3b 3a [2] 3d 0f [2] 13 0f [2] 2c 13 }

  condition:
    any of them
}