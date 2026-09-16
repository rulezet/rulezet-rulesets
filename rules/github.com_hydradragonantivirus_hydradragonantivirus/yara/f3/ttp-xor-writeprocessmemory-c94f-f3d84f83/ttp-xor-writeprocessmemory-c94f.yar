rule TTP_XOR_WriteProcessMemory_c94f {
  strings:
    $key_c94f = { 9e 3d [2] ac 1f [2] aa 2a [2] 84 2a [2] bb 36 }

  condition:
    any of them
}