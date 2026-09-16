rule TTP_XOR_WriteProcessMemory_4f7a {
  strings:
    $key_4f7a = { 18 08 [2] 2a 2a [2] 2c 1f [2] 02 1f [2] 3d 03 }

  condition:
    any of them
}