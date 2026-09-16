rule TTP_XOR_WriteProcessMemory_e3ce {
  strings:
    $key_e3ce = { b4 bc [2] 86 9e [2] 80 ab [2] ae ab [2] 91 b7 }

  condition:
    any of them
}