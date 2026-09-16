rule TTP_XOR_WriteProcessMemory_850b {
  strings:
    $key_850b = { d2 79 [2] e0 5b [2] e6 6e [2] c8 6e [2] f7 72 }

  condition:
    any of them
}