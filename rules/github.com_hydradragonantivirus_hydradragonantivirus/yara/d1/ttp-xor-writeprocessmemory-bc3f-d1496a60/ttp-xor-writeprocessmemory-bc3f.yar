rule TTP_XOR_WriteProcessMemory_bc3f {
  strings:
    $key_bc3f = { eb 4d [2] d9 6f [2] df 5a [2] f1 5a [2] ce 46 }

  condition:
    any of them
}