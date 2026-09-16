rule TTP_XOR_WriteProcessMemory_741f {
  strings:
    $key_741f = { 23 6d [2] 11 4f [2] 17 7a [2] 39 7a [2] 06 66 }

  condition:
    any of them
}