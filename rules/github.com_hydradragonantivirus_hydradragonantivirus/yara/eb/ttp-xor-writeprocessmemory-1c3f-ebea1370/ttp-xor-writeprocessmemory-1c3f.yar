rule TTP_XOR_WriteProcessMemory_1c3f {
  strings:
    $key_1c3f = { 4b 4d [2] 79 6f [2] 7f 5a [2] 51 5a [2] 6e 46 }

  condition:
    any of them
}