rule TTP_XOR_WriteProcessMemory_f64f {
  strings:
    $key_f64f = { a1 3d [2] 93 1f [2] 95 2a [2] bb 2a [2] 84 36 }

  condition:
    any of them
}