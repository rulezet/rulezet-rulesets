rule TTP_XOR_WriteProcessMemory_979c {
  strings:
    $key_979c = { c0 ee [2] f2 cc [2] f4 f9 [2] da f9 [2] e5 e5 }

  condition:
    any of them
}