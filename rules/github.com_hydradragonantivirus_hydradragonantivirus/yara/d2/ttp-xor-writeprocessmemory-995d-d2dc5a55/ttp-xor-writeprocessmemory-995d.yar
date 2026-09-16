rule TTP_XOR_WriteProcessMemory_995d {
  strings:
    $key_995d = { ce 2f [2] fc 0d [2] fa 38 [2] d4 38 [2] eb 24 }

  condition:
    any of them
}