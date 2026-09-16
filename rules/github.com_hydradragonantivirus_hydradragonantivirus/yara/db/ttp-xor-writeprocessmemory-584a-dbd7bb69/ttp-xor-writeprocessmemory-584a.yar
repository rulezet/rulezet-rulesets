rule TTP_XOR_WriteProcessMemory_584a {
  strings:
    $key_584a = { 0f 38 [2] 3d 1a [2] 3b 2f [2] 15 2f [2] 2a 33 }

  condition:
    any of them
}