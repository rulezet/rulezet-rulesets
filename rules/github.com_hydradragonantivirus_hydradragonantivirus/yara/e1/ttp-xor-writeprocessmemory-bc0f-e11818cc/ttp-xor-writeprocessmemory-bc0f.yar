rule TTP_XOR_WriteProcessMemory_bc0f {
  strings:
    $key_bc0f = { eb 7d [2] d9 5f [2] df 6a [2] f1 6a [2] ce 76 }

  condition:
    any of them
}