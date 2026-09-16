rule TTP_XOR_WriteProcessMemory_993d {
  strings:
    $key_993d = { ce 4f [2] fc 6d [2] fa 58 [2] d4 58 [2] eb 44 }

  condition:
    any of them
}