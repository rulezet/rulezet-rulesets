rule TTP_XOR_WriteProcessMemory_bc4a {
  strings:
    $key_bc4a = { eb 38 [2] d9 1a [2] df 2f [2] f1 2f [2] ce 33 }

  condition:
    any of them
}