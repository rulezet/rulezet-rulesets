rule TTP_XOR_WriteProcessMemory_ef7f {
  strings:
    $key_ef7f = { b8 0d [2] 8a 2f [2] 8c 1a [2] a2 1a [2] 9d 06 }

  condition:
    any of them
}