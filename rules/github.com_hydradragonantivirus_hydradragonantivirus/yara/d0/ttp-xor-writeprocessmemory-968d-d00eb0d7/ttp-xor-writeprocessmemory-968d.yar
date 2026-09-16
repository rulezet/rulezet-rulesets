rule TTP_XOR_WriteProcessMemory_968d {
  strings:
    $key_968d = { c1 ff [2] f3 dd [2] f5 e8 [2] db e8 [2] e4 f4 }

  condition:
    any of them
}