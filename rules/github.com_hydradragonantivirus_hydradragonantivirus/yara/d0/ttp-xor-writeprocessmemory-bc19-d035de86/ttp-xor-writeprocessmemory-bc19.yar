rule TTP_XOR_WriteProcessMemory_bc19 {
  strings:
    $key_bc19 = { eb 6b [2] d9 49 [2] df 7c [2] f1 7c [2] ce 60 }

  condition:
    any of them
}