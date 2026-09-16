rule TTP_XOR_WriteProcessMemory_2f2f {
  strings:
    $key_2f2f = { 78 5d [2] 4a 7f [2] 4c 4a [2] 62 4a [2] 5d 56 }

  condition:
    any of them
}