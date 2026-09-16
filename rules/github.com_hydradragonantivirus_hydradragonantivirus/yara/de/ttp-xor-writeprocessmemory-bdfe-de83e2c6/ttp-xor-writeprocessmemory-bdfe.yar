rule TTP_XOR_WriteProcessMemory_bdfe {
  strings:
    $key_bdfe = { ea 8c [2] d8 ae [2] de 9b [2] f0 9b [2] cf 87 }

  condition:
    any of them
}