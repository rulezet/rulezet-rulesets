rule TTP_XOR_WriteProcessMemory_bd09 {
  strings:
    $key_bd09 = { ea 7b [2] d8 59 [2] de 6c [2] f0 6c [2] cf 70 }

  condition:
    any of them
}