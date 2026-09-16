rule TTP_XOR_WriteProcessMemory_e3a4 {
  strings:
    $key_e3a4 = { b4 d6 [2] 86 f4 [2] 80 c1 [2] ae c1 [2] 91 dd }

  condition:
    any of them
}