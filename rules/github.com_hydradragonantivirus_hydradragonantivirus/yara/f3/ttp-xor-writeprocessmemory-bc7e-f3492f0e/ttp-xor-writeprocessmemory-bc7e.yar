rule TTP_XOR_WriteProcessMemory_bc7e {
  strings:
    $key_bc7e = { eb 0c [2] d9 2e [2] df 1b [2] f1 1b [2] ce 07 }

  condition:
    any of them
}