rule TTP_XOR_WriteProcessMemory_422a {
  strings:
    $key_422a = { 15 58 [2] 27 7a [2] 21 4f [2] 0f 4f [2] 30 53 }

  condition:
    any of them
}