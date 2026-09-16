rule TTP_XOR_WriteProcessMemory_ac49 {
  strings:
    $key_ac49 = { fb 3b [2] c9 19 [2] cf 2c [2] e1 2c [2] de 30 }

  condition:
    any of them
}