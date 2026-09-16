rule TTP_XOR_WriteProcessMemory_554f {
  strings:
    $key_554f = { 02 3d [2] 30 1f [2] 36 2a [2] 18 2a [2] 27 36 }

  condition:
    any of them
}