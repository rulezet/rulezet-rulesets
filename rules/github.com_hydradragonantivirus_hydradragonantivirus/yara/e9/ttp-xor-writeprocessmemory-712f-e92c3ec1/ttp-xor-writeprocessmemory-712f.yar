rule TTP_XOR_WriteProcessMemory_712f {
  strings:
    $key_712f = { 26 5d [2] 14 7f [2] 12 4a [2] 3c 4a [2] 03 56 }

  condition:
    any of them
}