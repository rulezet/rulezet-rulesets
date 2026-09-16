rule TTP_XOR_WriteProcessMemory_bc54 {
  strings:
    $key_bc54 = { eb 26 [2] d9 04 [2] df 31 [2] f1 31 [2] ce 2d }

  condition:
    any of them
}