rule TTP_XOR_WriteProcessMemory_818d {
  strings:
    $key_818d = { d6 ff [2] e4 dd [2] e2 e8 [2] cc e8 [2] f3 f4 }

  condition:
    any of them
}