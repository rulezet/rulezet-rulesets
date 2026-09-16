rule TTP_XOR_WriteProcessMemory_bd36 {
  strings:
    $key_bd36 = { ea 44 [2] d8 66 [2] de 53 [2] f0 53 [2] cf 4f }

  condition:
    any of them
}