rule TTP_XOR_WriteProcessMemory_134f {
  strings:
    $key_134f = { 44 3d [2] 76 1f [2] 70 2a [2] 5e 2a [2] 61 36 }

  condition:
    any of them
}