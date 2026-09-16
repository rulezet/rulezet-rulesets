rule TTP_XOR_WriteProcessMemory_022f {
  strings:
    $key_022f = { 55 5d [2] 67 7f [2] 61 4a [2] 4f 4a [2] 70 56 }

  condition:
    any of them
}