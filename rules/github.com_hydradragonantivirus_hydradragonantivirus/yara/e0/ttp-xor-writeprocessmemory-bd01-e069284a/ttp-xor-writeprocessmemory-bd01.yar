rule TTP_XOR_WriteProcessMemory_bd01 {
  strings:
    $key_bd01 = { ea 73 [2] d8 51 [2] de 64 [2] f0 64 [2] cf 78 }

  condition:
    any of them
}