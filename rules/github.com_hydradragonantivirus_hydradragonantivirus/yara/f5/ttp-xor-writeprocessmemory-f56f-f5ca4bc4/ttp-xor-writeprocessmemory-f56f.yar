rule TTP_XOR_WriteProcessMemory_f56f {
  strings:
    $key_f56f = { a2 1d [2] 90 3f [2] 96 0a [2] b8 0a [2] 87 16 }

  condition:
    any of them
}