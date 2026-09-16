rule TTP_XOR_WriteProcessMemory_c84f {
  strings:
    $key_c84f = { 9f 3d [2] ad 1f [2] ab 2a [2] 85 2a [2] ba 36 }

  condition:
    any of them
}