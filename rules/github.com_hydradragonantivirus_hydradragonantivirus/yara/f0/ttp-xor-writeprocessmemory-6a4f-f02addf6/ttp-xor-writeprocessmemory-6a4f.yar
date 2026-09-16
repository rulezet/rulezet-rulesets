rule TTP_XOR_WriteProcessMemory_6a4f {
  strings:
    $key_6a4f = { 3d 3d [2] 0f 1f [2] 09 2a [2] 27 2a [2] 18 36 }

  condition:
    any of them
}