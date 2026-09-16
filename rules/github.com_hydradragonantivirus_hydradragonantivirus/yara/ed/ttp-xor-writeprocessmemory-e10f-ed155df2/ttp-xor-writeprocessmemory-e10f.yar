rule TTP_XOR_WriteProcessMemory_e10f {
  strings:
    $key_e10f = { b6 7d [2] 84 5f [2] 82 6a [2] ac 6a [2] 93 76 }

  condition:
    any of them
}