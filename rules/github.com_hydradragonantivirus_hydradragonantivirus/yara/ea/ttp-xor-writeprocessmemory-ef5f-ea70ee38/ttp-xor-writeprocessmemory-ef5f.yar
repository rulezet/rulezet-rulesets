rule TTP_XOR_WriteProcessMemory_ef5f {
  strings:
    $key_ef5f = { b8 2d [2] 8a 0f [2] 8c 3a [2] a2 3a [2] 9d 26 }

  condition:
    any of them
}