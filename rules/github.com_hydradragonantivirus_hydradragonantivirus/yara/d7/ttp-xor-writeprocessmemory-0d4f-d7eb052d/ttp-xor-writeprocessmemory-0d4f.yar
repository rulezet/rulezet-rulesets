rule TTP_XOR_WriteProcessMemory_0d4f {
  strings:
    $key_0d4f = { 5a 3d [2] 68 1f [2] 6e 2a [2] 40 2a [2] 7f 36 }

  condition:
    any of them
}