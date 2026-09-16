rule TTP_XOR_WriteProcessMemory_e39c {
  strings:
    $key_e39c = { b4 ee [2] 86 cc [2] 80 f9 [2] ae f9 [2] 91 e5 }

  condition:
    any of them
}