rule TTP_XOR_WriteProcessMemory_453f {
  strings:
    $key_453f = { 12 4d [2] 20 6f [2] 26 5a [2] 08 5a [2] 37 46 }

  condition:
    any of them
}