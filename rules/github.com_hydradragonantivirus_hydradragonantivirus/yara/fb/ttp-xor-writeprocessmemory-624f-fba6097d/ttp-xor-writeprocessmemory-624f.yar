rule TTP_XOR_WriteProcessMemory_624f {
  strings:
    $key_624f = { 35 3d [2] 07 1f [2] 01 2a [2] 2f 2a [2] 10 36 }

  condition:
    any of them
}