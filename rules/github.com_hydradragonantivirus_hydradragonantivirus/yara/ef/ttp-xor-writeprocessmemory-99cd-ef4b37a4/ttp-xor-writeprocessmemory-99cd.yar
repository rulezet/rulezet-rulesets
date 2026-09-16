rule TTP_XOR_WriteProcessMemory_99cd {
  strings:
    $key_99cd = { ce bf [2] fc 9d [2] fa a8 [2] d4 a8 [2] eb b4 }

  condition:
    any of them
}