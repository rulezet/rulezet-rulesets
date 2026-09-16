rule TTP_XOR_WriteProcessMemory_bd39 {
  strings:
    $key_bd39 = { ea 4b [2] d8 69 [2] de 5c [2] f0 5c [2] cf 40 }

  condition:
    any of them
}