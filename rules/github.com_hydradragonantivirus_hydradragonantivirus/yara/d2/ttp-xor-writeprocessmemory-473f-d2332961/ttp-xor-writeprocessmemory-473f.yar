rule TTP_XOR_WriteProcessMemory_473f {
  strings:
    $key_473f = { 10 4d [2] 22 6f [2] 24 5a [2] 0a 5a [2] 35 46 }

  condition:
    any of them
}