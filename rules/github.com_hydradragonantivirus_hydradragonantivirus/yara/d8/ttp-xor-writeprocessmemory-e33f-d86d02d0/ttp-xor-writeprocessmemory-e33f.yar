rule TTP_XOR_WriteProcessMemory_e33f {
  strings:
    $key_e33f = { b4 4d [2] 86 6f [2] 80 5a [2] ae 5a [2] 91 46 }

  condition:
    any of them
}