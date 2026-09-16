rule TTP_XOR_WriteProcessMemory_3d2f {
  strings:
    $key_3d2f = { 6a 5d [2] 58 7f [2] 5e 4a [2] 70 4a [2] 4f 56 }

  condition:
    any of them
}