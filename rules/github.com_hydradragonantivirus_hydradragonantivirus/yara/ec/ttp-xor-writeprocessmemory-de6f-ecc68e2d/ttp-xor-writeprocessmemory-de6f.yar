rule TTP_XOR_WriteProcessMemory_de6f {
  strings:
    $key_de6f = { 89 1d [2] bb 3f [2] bd 0a [2] 93 0a [2] ac 16 }

  condition:
    any of them
}