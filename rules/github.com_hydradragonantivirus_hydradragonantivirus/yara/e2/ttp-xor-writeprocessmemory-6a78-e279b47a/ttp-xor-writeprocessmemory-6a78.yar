rule TTP_XOR_WriteProcessMemory_6a78 {
  strings:
    $key_6a78 = { 3d 0a [2] 0f 28 [2] 09 1d [2] 27 1d [2] 18 01 }

  condition:
    any of them
}