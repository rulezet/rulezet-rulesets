rule TTP_XOR_WriteProcessMemory_5e3a {
  strings:
    $key_5e3a = { 09 48 [2] 3b 6a [2] 3d 5f [2] 13 5f [2] 2c 43 }

  condition:
    any of them
}