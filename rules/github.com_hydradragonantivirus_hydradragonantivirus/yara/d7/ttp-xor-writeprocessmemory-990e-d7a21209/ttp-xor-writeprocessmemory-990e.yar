rule TTP_XOR_WriteProcessMemory_990e {
  strings:
    $key_990e = { ce 7c [2] fc 5e [2] fa 6b [2] d4 6b [2] eb 77 }

  condition:
    any of them
}