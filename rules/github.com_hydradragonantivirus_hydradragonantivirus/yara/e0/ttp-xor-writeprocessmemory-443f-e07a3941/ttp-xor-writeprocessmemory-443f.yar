rule TTP_XOR_WriteProcessMemory_443f {
  strings:
    $key_443f = { 13 4d [2] 21 6f [2] 27 5a [2] 09 5a [2] 36 46 }

  condition:
    any of them
}