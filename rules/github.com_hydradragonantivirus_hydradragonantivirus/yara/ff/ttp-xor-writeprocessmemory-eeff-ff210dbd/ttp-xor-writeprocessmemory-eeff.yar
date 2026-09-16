rule TTP_XOR_WriteProcessMemory_eeff {
  strings:
    $key_eeff = { b9 8d [2] 8b af [2] 8d 9a [2] a3 9a [2] 9c 86 }

  condition:
    any of them
}