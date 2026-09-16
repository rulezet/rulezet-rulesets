rule TTP_XOR_WriteProcessMemory_defe {
  strings:
    $key_defe = { 89 8c [2] bb ae [2] bd 9b [2] 93 9b [2] ac 87 }

  condition:
    any of them
}