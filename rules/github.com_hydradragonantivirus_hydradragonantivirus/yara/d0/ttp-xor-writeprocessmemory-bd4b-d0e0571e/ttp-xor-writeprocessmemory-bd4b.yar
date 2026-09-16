rule TTP_XOR_WriteProcessMemory_bd4b {
  strings:
    $key_bd4b = { ea 39 [2] d8 1b [2] de 2e [2] f0 2e [2] cf 32 }

  condition:
    any of them
}