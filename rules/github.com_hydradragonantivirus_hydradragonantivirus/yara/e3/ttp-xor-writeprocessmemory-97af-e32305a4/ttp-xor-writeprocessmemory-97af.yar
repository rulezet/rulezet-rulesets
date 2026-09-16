rule TTP_XOR_WriteProcessMemory_97af {
  strings:
    $key_97af = { c0 dd [2] f2 ff [2] f4 ca [2] da ca [2] e5 d6 }

  condition:
    any of them
}