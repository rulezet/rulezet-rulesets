rule TTP_XOR_WriteProcessMemory_be93 {
  strings:
    $key_be93 = { e9 e1 [2] db c3 [2] dd f6 [2] f3 f6 [2] cc ea }

  condition:
    any of them
}