rule TTP_XOR_WriteProcessMemory_f54f {
  strings:
    $key_f54f = { a2 3d [2] 90 1f [2] 96 2a [2] b8 2a [2] 87 36 }

  condition:
    any of them
}