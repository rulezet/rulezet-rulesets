rule TTP_XOR_WriteProcessMemory_5e2a {
  strings:
    $key_5e2a = { 09 58 [2] 3b 7a [2] 3d 4f [2] 13 4f [2] 2c 53 }

  condition:
    any of them
}