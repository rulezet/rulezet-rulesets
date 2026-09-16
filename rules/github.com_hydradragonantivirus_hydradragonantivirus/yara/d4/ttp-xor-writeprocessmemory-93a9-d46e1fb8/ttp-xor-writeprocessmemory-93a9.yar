rule TTP_XOR_WriteProcessMemory_93a9 {
  strings:
    $key_93a9 = { c4 db [2] f6 f9 [2] f0 cc [2] de cc [2] e1 d0 }

  condition:
    any of them
}