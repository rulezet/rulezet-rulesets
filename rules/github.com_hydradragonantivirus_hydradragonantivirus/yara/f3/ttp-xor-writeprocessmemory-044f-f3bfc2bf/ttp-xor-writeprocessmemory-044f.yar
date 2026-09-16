rule TTP_XOR_WriteProcessMemory_044f {
  strings:
    $key_044f = { 53 3d [2] 61 1f [2] 67 2a [2] 49 2a [2] 76 36 }

  condition:
    any of them
}