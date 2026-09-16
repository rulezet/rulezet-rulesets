rule TTP_XOR_WriteProcessMemory_553f {
  strings:
    $key_553f = { 02 4d [2] 30 6f [2] 36 5a [2] 18 5a [2] 27 46 }

  condition:
    any of them
}