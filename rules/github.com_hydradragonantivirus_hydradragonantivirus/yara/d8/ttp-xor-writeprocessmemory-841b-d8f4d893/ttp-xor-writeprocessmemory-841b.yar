rule TTP_XOR_WriteProcessMemory_841b {
  strings:
    $key_841b = { d3 69 [2] e1 4b [2] e7 7e [2] c9 7e [2] f6 62 }

  condition:
    any of them
}