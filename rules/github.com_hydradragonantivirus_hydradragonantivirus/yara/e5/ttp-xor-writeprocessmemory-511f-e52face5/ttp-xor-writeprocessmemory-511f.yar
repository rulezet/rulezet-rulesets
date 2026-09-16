rule TTP_XOR_WriteProcessMemory_511f {
  strings:
    $key_511f = { 06 6d [2] 34 4f [2] 32 7a [2] 1c 7a [2] 23 66 }

  condition:
    any of them
}