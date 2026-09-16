rule TTP_XOR_WriteProcessMemory_c96f {
  strings:
    $key_c96f = { 9e 1d [2] ac 3f [2] aa 0a [2] 84 0a [2] bb 16 }

  condition:
    any of them
}