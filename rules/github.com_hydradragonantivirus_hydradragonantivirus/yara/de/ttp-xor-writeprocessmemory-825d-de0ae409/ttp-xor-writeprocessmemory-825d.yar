rule TTP_XOR_WriteProcessMemory_825d {
  strings:
    $key_825d = { d5 2f [2] e7 0d [2] e1 38 [2] cf 38 [2] f0 24 }

  condition:
    any of them
}