rule TTP_XOR_WriteProcessMemory_822c {
  strings:
    $key_822c = { d5 5e [2] e7 7c [2] e1 49 [2] cf 49 [2] f0 55 }

  condition:
    any of them
}