rule TTP_XOR_WriteProcessMemory_996d {
  strings:
    $key_996d = { ce 1f [2] fc 3d [2] fa 08 [2] d4 08 [2] eb 14 }

  condition:
    any of them
}