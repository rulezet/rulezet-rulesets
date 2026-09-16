rule TTP_XOR_WriteProcessMemory_996b {
  strings:
    $key_996b = { ce 19 [2] fc 3b [2] fa 0e [2] d4 0e [2] eb 12 }

  condition:
    any of them
}