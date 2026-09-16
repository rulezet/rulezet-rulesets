rule TTP_XOR_WriteProcessMemory_304f {
  strings:
    $key_304f = { 67 3d [2] 55 1f [2] 53 2a [2] 7d 2a [2] 42 36 }

  condition:
    any of them
}