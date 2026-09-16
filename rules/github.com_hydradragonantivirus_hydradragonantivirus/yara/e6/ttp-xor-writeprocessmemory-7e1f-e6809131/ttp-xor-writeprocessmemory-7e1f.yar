rule TTP_XOR_WriteProcessMemory_7e1f {
  strings:
    $key_7e1f = { 29 6d [2] 1b 4f [2] 1d 7a [2] 33 7a [2] 0c 66 }

  condition:
    any of them
}