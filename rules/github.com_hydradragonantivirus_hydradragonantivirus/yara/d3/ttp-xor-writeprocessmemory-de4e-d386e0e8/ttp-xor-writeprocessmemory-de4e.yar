rule TTP_XOR_WriteProcessMemory_de4e {
  strings:
    $key_de4e = { 89 3c [2] bb 1e [2] bd 2b [2] 93 2b [2] ac 37 }

  condition:
    any of them
}