rule TTP_XOR_WriteProcessMemory_98af {
  strings:
    $key_98af = { cf dd [2] fd ff [2] fb ca [2] d5 ca [2] ea d6 }

  condition:
    any of them
}