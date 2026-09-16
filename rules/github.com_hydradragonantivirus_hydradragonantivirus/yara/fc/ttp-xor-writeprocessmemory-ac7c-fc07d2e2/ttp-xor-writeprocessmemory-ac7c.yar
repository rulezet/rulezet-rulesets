rule TTP_XOR_WriteProcessMemory_ac7c {
  strings:
    $key_ac7c = { fb 0e [2] c9 2c [2] cf 19 [2] e1 19 [2] de 05 }

  condition:
    any of them
}