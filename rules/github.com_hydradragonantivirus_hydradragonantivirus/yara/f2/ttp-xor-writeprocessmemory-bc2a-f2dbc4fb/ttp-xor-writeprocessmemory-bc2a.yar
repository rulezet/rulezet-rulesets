rule TTP_XOR_WriteProcessMemory_bc2a {
  strings:
    $key_bc2a = { eb 58 [2] d9 7a [2] df 4f [2] f1 4f [2] ce 53 }

  condition:
    any of them
}