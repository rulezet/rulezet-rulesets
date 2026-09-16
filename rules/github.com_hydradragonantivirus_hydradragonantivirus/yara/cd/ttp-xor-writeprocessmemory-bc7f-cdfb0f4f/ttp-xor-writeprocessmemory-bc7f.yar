rule TTP_XOR_WriteProcessMemory_bc7f {
  strings:
    $key_bc7f = { eb 0d [2] d9 2f [2] df 1a [2] f1 1a [2] ce 06 }

  condition:
    any of them
}