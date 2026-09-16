rule TTP_XOR_WriteProcessMemory_ac3e {
  strings:
    $key_ac3e = { fb 4c [2] c9 6e [2] cf 5b [2] e1 5b [2] de 47 }

  condition:
    any of them
}