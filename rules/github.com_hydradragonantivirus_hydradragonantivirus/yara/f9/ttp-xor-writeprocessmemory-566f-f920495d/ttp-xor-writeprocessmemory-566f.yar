rule TTP_XOR_WriteProcessMemory_566f {
  strings:
    $key_566f = { 01 1d [2] 33 3f [2] 35 0a [2] 1b 0a [2] 24 16 }

  condition:
    any of them
}