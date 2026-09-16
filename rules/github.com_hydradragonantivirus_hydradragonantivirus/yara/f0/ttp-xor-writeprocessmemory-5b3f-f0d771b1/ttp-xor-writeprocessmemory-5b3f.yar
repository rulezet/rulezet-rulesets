rule TTP_XOR_WriteProcessMemory_5b3f {
  strings:
    $key_5b3f = { 0c 4d [2] 3e 6f [2] 38 5a [2] 16 5a [2] 29 46 }

  condition:
    any of them
}