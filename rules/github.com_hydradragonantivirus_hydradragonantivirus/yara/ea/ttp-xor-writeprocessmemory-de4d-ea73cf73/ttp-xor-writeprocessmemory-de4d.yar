rule TTP_XOR_WriteProcessMemory_de4d {
  strings:
    $key_de4d = { 89 3f [2] bb 1d [2] bd 28 [2] 93 28 [2] ac 34 }

  condition:
    any of them
}