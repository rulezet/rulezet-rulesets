rule TTP_XOR_WriteProcessMemory_154f {
  strings:
    $key_154f = { 42 3d [2] 70 1f [2] 76 2a [2] 58 2a [2] 67 36 }

  condition:
    any of them
}