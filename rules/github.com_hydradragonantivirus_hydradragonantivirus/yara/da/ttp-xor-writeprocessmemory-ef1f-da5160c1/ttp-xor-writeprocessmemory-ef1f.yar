rule TTP_XOR_WriteProcessMemory_ef1f {
  strings:
    $key_ef1f = { b8 6d [2] 8a 4f [2] 8c 7a [2] a2 7a [2] 9d 66 }

  condition:
    any of them
}