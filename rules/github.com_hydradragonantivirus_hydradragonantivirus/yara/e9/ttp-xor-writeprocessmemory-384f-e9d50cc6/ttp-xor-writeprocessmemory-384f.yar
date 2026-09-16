rule TTP_XOR_WriteProcessMemory_384f {
  strings:
    $key_384f = { 6f 3d [2] 5d 1f [2] 5b 2a [2] 75 2a [2] 4a 36 }

  condition:
    any of them
}