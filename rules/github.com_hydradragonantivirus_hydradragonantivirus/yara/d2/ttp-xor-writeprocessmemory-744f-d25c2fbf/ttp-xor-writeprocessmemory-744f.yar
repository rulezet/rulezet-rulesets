rule TTP_XOR_WriteProcessMemory_744f {
  strings:
    $key_744f = { 23 3d [2] 11 1f [2] 17 2a [2] 39 2a [2] 06 36 }

  condition:
    any of them
}