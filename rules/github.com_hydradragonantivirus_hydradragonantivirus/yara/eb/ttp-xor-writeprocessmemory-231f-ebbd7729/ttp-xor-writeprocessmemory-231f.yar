rule TTP_XOR_WriteProcessMemory_231f {
  strings:
    $key_231f = { 74 6d [2] 46 4f [2] 40 7a [2] 6e 7a [2] 51 66 }

  condition:
    any of them
}