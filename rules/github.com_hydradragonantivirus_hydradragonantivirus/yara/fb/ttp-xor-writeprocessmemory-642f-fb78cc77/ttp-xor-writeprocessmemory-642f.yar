rule TTP_XOR_WriteProcessMemory_642f {
  strings:
    $key_642f = { 33 5d [2] 01 7f [2] 07 4a [2] 29 4a [2] 16 56 }

  condition:
    any of them
}