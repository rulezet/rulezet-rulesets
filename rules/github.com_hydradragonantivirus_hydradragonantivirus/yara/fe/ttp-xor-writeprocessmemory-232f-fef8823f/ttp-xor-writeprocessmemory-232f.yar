rule TTP_XOR_WriteProcessMemory_232f {
  strings:
    $key_232f = { 74 5d [2] 46 7f [2] 40 4a [2] 6e 4a [2] 51 56 }

  condition:
    any of them
}