rule TTP_XOR_WriteProcessMemory_066f {
  strings:
    $key_066f = { 51 1d [2] 63 3f [2] 65 0a [2] 4b 0a [2] 74 16 }

  condition:
    any of them
}