rule TTP_XOR_WriteProcessMemory_7b4f {
  strings:
    $key_7b4f = { 2c 3d [2] 1e 1f [2] 18 2a [2] 36 2a [2] 09 36 }

  condition:
    any of them
}