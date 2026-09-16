rule TTP_XOR_WriteProcessMemory_775f {
  strings:
    $key_775f = { 20 2d [2] 12 0f [2] 14 3a [2] 3a 3a [2] 05 26 }

  condition:
    any of them
}