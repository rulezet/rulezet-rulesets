rule TTP_XOR_WriteProcessMemory_743f {
  strings:
    $key_743f = { 23 4d [2] 11 6f [2] 17 5a [2] 39 5a [2] 06 46 }

  condition:
    any of them
}