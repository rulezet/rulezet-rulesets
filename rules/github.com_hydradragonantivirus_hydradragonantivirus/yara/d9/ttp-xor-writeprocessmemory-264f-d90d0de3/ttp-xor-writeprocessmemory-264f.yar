rule TTP_XOR_WriteProcessMemory_264f {
  strings:
    $key_264f = { 71 3d [2] 43 1f [2] 45 2a [2] 6b 2a [2] 54 36 }

  condition:
    any of them
}