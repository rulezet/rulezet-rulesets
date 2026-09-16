rule TTP_XOR_WriteProcessMemory_5e0a {
  strings:
    $key_5e0a = { 09 78 [2] 3b 5a [2] 3d 6f [2] 13 6f [2] 2c 73 }

  condition:
    any of them
}