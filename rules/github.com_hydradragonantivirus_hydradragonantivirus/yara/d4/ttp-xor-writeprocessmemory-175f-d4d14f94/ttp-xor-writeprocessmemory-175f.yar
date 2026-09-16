rule TTP_XOR_WriteProcessMemory_175f {
  strings:
    $key_175f = { 40 2d [2] 72 0f [2] 74 3a [2] 5a 3a [2] 65 26 }

  condition:
    any of them
}