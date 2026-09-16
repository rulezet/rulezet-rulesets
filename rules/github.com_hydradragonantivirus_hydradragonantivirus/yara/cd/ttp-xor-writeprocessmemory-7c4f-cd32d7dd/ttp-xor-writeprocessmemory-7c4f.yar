rule TTP_XOR_WriteProcessMemory_7c4f {
  strings:
    $key_7c4f = { 2b 3d [2] 19 1f [2] 1f 2a [2] 31 2a [2] 0e 36 }

  condition:
    any of them
}