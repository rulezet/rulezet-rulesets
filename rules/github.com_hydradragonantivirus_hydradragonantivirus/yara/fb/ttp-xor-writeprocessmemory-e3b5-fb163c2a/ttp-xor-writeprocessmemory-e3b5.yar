rule TTP_XOR_WriteProcessMemory_e3b5 {
  strings:
    $key_e3b5 = { b4 c7 [2] 86 e5 [2] 80 d0 [2] ae d0 [2] 91 cc }

  condition:
    any of them
}