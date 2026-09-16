rule TTP_XOR_WriteProcessMemory_bdad {
  strings:
    $key_bdad = { ea df [2] d8 fd [2] de c8 [2] f0 c8 [2] cf d4 }

  condition:
    any of them
}