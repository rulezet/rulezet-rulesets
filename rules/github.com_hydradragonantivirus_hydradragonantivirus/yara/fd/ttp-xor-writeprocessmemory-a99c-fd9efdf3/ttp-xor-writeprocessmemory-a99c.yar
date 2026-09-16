rule TTP_XOR_WriteProcessMemory_a99c {
  strings:
    $key_a99c = { fe ee [2] cc cc [2] ca f9 [2] e4 f9 [2] db e5 }

  condition:
    any of them
}