rule TTP_XOR_WriteProcessMemory_2f1f {
  strings:
    $key_2f1f = { 78 6d [2] 4a 4f [2] 4c 7a [2] 62 7a [2] 5d 66 }

  condition:
    any of them
}