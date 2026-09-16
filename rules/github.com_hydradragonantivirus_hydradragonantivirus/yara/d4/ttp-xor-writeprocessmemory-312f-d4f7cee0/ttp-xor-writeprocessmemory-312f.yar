rule TTP_XOR_WriteProcessMemory_312f {
  strings:
    $key_312f = { 66 5d [2] 54 7f [2] 52 4a [2] 7c 4a [2] 43 56 }

  condition:
    any of them
}