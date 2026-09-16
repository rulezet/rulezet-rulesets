rule TTP_XOR_WriteProcessMemory_f24f {
  strings:
    $key_f24f = { a5 3d [2] 97 1f [2] 91 2a [2] bf 2a [2] 80 36 }

  condition:
    any of them
}