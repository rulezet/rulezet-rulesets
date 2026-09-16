rule TTP_XOR_WriteProcessMemory_3d6a {
  strings:
    $key_3d6a = { 6a 18 [2] 58 3a [2] 5e 0f [2] 70 0f [2] 4f 13 }

  condition:
    any of them
}