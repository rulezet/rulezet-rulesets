rule TTP_XOR_WriteProcessMemory_514f {
  strings:
    $key_514f = { 06 3d [2] 34 1f [2] 32 2a [2] 1c 2a [2] 23 36 }

  condition:
    any of them
}