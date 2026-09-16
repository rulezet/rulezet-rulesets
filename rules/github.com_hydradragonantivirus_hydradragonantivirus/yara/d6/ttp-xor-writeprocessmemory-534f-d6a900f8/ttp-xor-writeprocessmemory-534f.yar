rule TTP_XOR_WriteProcessMemory_534f {
  strings:
    $key_534f = { 04 3d [2] 36 1f [2] 30 2a [2] 1e 2a [2] 21 36 }

  condition:
    any of them
}