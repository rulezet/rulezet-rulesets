rule TTP_XOR_WriteProcessMemory_130f {
  strings:
    $key_130f = { 44 7d [2] 76 5f [2] 70 6a [2] 5e 6a [2] 61 76 }

  condition:
    any of them
}