rule TTP_XOR_WriteProcessMemory_6a3f {
  strings:
    $key_6a3f = { 3d 4d [2] 0f 6f [2] 09 5a [2] 27 5a [2] 18 46 }

  condition:
    any of them
}