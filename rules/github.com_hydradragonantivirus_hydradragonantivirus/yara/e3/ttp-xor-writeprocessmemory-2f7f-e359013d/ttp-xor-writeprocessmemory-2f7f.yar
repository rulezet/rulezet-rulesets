rule TTP_XOR_WriteProcessMemory_2f7f {
  strings:
    $key_2f7f = { 78 0d [2] 4a 2f [2] 4c 1a [2] 62 1a [2] 5d 06 }

  condition:
    any of them
}