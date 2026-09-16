rule TTP_XOR_WriteProcessMemory_e3a2 {
  strings:
    $key_e3a2 = { b4 d0 [2] 86 f2 [2] 80 c7 [2] ae c7 [2] 91 db }

  condition:
    any of them
}