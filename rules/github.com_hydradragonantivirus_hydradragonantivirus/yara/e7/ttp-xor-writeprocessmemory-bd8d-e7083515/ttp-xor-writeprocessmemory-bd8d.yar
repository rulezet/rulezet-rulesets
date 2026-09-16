rule TTP_XOR_WriteProcessMemory_bd8d {
  strings:
    $key_bd8d = { ea ff [2] d8 dd [2] de e8 [2] f0 e8 [2] cf f4 }

  condition:
    any of them
}