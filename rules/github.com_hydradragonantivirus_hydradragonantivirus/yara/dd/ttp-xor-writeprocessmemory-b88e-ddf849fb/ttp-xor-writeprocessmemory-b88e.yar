rule TTP_XOR_WriteProcessMemory_b88e {
  strings:
    $key_b88e = { ef fc [2] dd de [2] db eb [2] f5 eb [2] ca f7 }

  condition:
    any of them
}