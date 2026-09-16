rule TTP_XOR_WriteProcessMemory_bd3f {
  strings:
    $key_bd3f = { ea 4d [2] d8 6f [2] de 5a [2] f0 5a [2] cf 46 }

  condition:
    any of them
}