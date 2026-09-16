rule TTP_XOR_WriteProcessMemory_bdbe {
  strings:
    $key_bdbe = { ea cc [2] d8 ee [2] de db [2] f0 db [2] cf c7 }

  condition:
    any of them
}