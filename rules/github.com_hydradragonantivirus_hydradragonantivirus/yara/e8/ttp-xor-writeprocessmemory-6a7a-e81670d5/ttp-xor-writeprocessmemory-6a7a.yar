rule TTP_XOR_WriteProcessMemory_6a7a {
  strings:
    $key_6a7a = { 3d 08 [2] 0f 2a [2] 09 1f [2] 27 1f [2] 18 03 }

  condition:
    any of them
}