rule TTP_XOR_WriteProcessMemory_787f {
  strings:
    $key_787f = { 2f 0d [2] 1d 2f [2] 1b 1a [2] 35 1a [2] 0a 06 }

  condition:
    any of them
}