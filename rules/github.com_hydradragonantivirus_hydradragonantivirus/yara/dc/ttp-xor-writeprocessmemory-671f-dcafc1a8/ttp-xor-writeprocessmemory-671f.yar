rule TTP_XOR_WriteProcessMemory_671f {
  strings:
    $key_671f = { 30 6d [2] 02 4f [2] 04 7a [2] 2a 7a [2] 15 66 }

  condition:
    any of them
}