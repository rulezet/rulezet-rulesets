rule TTP_XOR_WriteProcessMemory_ef6f {
  strings:
    $key_ef6f = { b8 1d [2] 8a 3f [2] 8c 0a [2] a2 0a [2] 9d 16 }

  condition:
    any of them
}