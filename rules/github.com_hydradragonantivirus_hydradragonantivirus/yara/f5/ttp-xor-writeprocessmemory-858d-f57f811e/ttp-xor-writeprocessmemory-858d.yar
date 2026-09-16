rule TTP_XOR_WriteProcessMemory_858d {
  strings:
    $key_858d = { d2 ff [2] e0 dd [2] e6 e8 [2] c8 e8 [2] f7 f4 }

  condition:
    any of them
}