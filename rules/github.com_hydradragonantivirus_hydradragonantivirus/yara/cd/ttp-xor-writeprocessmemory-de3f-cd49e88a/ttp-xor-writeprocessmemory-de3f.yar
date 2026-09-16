rule TTP_XOR_WriteProcessMemory_de3f {
  strings:
    $key_de3f = { 89 4d [2] bb 6f [2] bd 5a [2] 93 5a [2] ac 46 }

  condition:
    any of them
}